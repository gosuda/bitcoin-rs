//! Switching the applied chain from one tip to another.

use crate::{
    ApplyError, ChainTransition, Chainstate, ConnectOutcome, DisconnectError, DisconnectOutcome,
};
use bitcoin_rs_chain::{NodeId, ReorgPlan, plan_reorg};
use bitcoin_rs_primitives::{Block, DecodeError, Hash256, deserialize};
use bitcoin_rs_storage::StorageError;

/// Maximum number of disconnect-side block bodies held in memory at once
/// during the streaming execution pass.
const DISCONNECT_STREAM_WINDOW: usize = 8;
const CONNECT_STREAM_WINDOW: usize = DISCONNECT_STREAM_WINDOW;

/// Node-owned work that follows committed reorg steps.
pub trait ReorgObserver {
    /// A block was fully disconnected.
    fn disconnected(&mut self, outcome: &DisconnectOutcome);

    /// A block was fully connected.
    fn connected(&mut self, block: &Block, outcome: &ConnectOutcome);

    /// Revisit one disconnected block in dependency order after a coherent
    /// branch switch. Bodies are streamed one at a time. The observer reads
    /// any chain facts it needs through its own admission view.
    fn reconsider_disconnected(&mut self, block: &Block);
}

/// Invalidates `hash` and its descendants, then moves applied chainstate to the
/// best remaining valid tip.
pub fn invalidate_block<O, S>(
    handles: &Chainstate,
    observer: &mut O,
    hash: Hash256,
    mut settle: S,
) -> core::result::Result<Box<[Hash256]>, ReorgError>
where
    O: ReorgObserver + ?Sized,
    S: FnMut(&mut O, core::result::Result<(), ReorgError>) -> core::result::Result<(), ReorgError>,
{
    // Validate the block exists and is not genesis before taking mutation
    // authority. Read-only refusal should not acquire the transition.
    let validation = (|| {
        let tree = handles.block_tree.read();
        let root = tree.lookup(hash).ok_or(ReorgError::UnknownBlock(hash))?;
        if tree.node(root).map_err(ReorgError::Plan)?.height == 0 {
            return Err(ReorgError::CannotInvalidateGenesis);
        }
        Ok(())
    })();
    if let Err(error) = validation {
        return settle_reorg_without_transition(handles, observer, Err(error), &mut settle)
            .map(|()| Box::default());
    }

    let transition = match handles.begin_transition() {
        Ok(transition) => transition,
        Err(source) => {
            return settle_reorg_without_transition(
                handles,
                observer,
                Err(ReorgError::Unavailable(Box::new(source))),
                &mut settle,
            )
            .map(|()| Box::default());
        }
    };
    let mut invalidated: Box<[Hash256]> = Box::default();
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
        let prepared = prepare_branches(handles, plan.as_ref(), &mut no_staged_body)?;
        let _retention = &prepared.retention;
        let (progress, outcome) = execute_streamed_plan(
            &transition,
            observer,
            &prepared.disconnect_nodes,
            &prepared.connect_nodes[..prepared.connect_limit()],
            &prepared.connect,
            &mut no_staged_body,
        );
        if progress.disconnected == prepared.disconnect_nodes.len()
            && !outcome.as_ref().is_err_and(ReorgError::requires_recovery)
        {
            invalidated = invalidate_and_republish(handles, hash)?;
        }
        if outcome.as_ref().is_err_and(ReorgError::requires_recovery) {
            outcome
        } else {
            let outcome = match (outcome, prepared.missing_connect) {
                (Ok(()), Some((hash, height))) => Err(ReorgError::MissingBody { hash, height }),
                (outcome, _) => outcome,
            };
            attach_reconsideration(
                outcome,
                revisit_disconnected_blocks(
                    handles,
                    observer,
                    &prepared.disconnect_nodes,
                    progress.disconnected,
                    &mut no_staged_body,
                ),
            )
        }
    })();
    settle_reorg_transition(transition, observer, outcome, &mut settle).map(|()| invalidated)
}

/// Why a subtree invalidation could not complete.
#[derive(Debug, thiserror::Error)]
pub(super) enum InvalidationError {
    /// The requested block hash has no header node.
    #[error("unknown block {0}")]
    UnknownBlock(Hash256),
    /// Invalidation left no valid chain tip.
    #[error("invalidation left no valid chain tip")]
    NoValidTip,
    /// Tree planning refused the invalidation.
    #[error("invalidation plan failed: {0}")]
    Plan(#[source] bitcoin_rs_chain::ChainError),
}

impl From<InvalidationError> for ReorgError {
    fn from(error: InvalidationError) -> Self {
        match error {
            InvalidationError::UnknownBlock(hash) => Self::UnknownBlock(hash),
            InvalidationError::NoValidTip => Self::NoValidTip,
            InvalidationError::Plan(source) => Self::Plan(source),
        }
    }
}

/// Marks `hash`'s subtree invalid and republishes the chain facts that derive
/// from the tree, under one tree write lock.
pub(super) fn invalidate_and_republish(
    handles: &Chainstate,
    hash: Hash256,
) -> core::result::Result<Box<[Hash256]>, InvalidationError> {
    let mut tree = handles.block_tree.write();
    let root = tree
        .lookup(hash)
        .ok_or(InvalidationError::UnknownBlock(hash))?;
    let invalidated = tree
        .invalidate_subtree(root)
        .map_err(InvalidationError::Plan)?;
    let tip = tree.tip().ok_or(InvalidationError::NoValidTip)?;
    handles.chain_tip.store(Some(tip));
    handles.reevaluate_assume_valid_with(&tree);
    Ok(invalidated.into_boxed_slice())
}

/// Why a branch switch stopped, and what the chain looks like now.
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
    /// No applied tip exists yet.
    #[error("no applied tip; the chain cannot be switched before genesis is applied")]
    NoAppliedTip,
    /// Planning failed: the two tips share no ancestor, or a node is unknown.
    #[error("reorg planning failed: {0}")]
    Plan(#[source] bitcoin_rs_chain::ChainError),
    /// A block in the remaining target branch has no stored body.
    #[error("no stored body for block {hash} at height {height}")]
    MissingBody {
        /// Block whose body is absent.
        hash: Hash256,
        /// Height it sits at.
        height: u32,
    },
    /// Reading a durable block body failed.
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
    /// A target-branch body became unreadable after the switch started.
    #[error(
        "reorg stopped at height {stopped_at} after {disconnected} disconnects and {connected} connects: body lost mid-switch: {source}"
    )]
    ConnectBodyLost {
        /// Fully disconnected blocks before the loss, in plan order.
        disconnected: usize,
        /// Fully connected new-branch blocks before the loss, in plan order.
        connected: usize,
        /// Height the applied tip reached before stopping.
        stopped_at: u32,
        /// Why the body could not be loaded.
        #[source]
        source: Box<Self>,
    },
    /// A connect failed while applying the new branch.
    #[error(
        "reorg target connect failed after reaching height {stopped_at} at block {hash}: {source}"
    )]
    ConnectFailed {
        /// Fully disconnected blocks before the failure, in plan order.
        disconnected: usize,
        /// Fully connected new-branch blocks before the failure, in plan order.
        connected: usize,
        /// Hash of the block that failed to connect.
        hash: Hash256,
        /// Height the applied tip reached when the target connect failed.
        stopped_at: u32,
        /// Why the connect failed.
        #[source]
        source: Box<ApplyError>,
        /// Whether the failure invalidates the branch, only this body, or
        /// neither. This is decided by the apply classifier at the failure.
        disposition: crate::WindowApplyDisposition,
        /// Hashes of the invalid subtree, in deterministic slab order, when the
        /// failure was allowlisted for permanent invalidation. Empty for
        /// body mutation and operational failures.
        invalidated: Vec<Hash256>,
    },
    /// Marking a permanently-invalid subtree `Invalid` or republishing the
    /// tip failed after a connect already failed.
    #[error("post-connect invalidation failed: {source}; original: {original}")]
    Invalidation {
        /// `UnknownBlock`/`Plan`/`NoValidTip` from the invalidation attempt.
        #[source]
        source: Box<Self>,
        /// The connect failure that triggered the invalidation.
        original: Box<Self>,
    },
    /// Reconnecting the old branch after a permanently invalid first target
    /// body failed. Some restoration steps may have committed, so admission
    /// stays closed until recovery reconciles the durable head and UTXO set.
    #[error(
        "reorg could not restore the previously applied branch: {source}; original: {original}"
    )]
    RestorationFailed {
        /// Read, validation, or durable failure during old-branch restoration.
        #[source]
        source: Box<Self>,
        /// Permanent target-connect failure that triggered restoration.
        original: Box<Self>,
    },
    /// A disconnect died partway. The chainstate is torn.
    #[error("reorg left the chainstate inconsistent: {0}")]
    Fatal(#[source] Box<DisconnectError>),
    /// Node-side settlement failed after the authoritative chain walk.
    #[error("reorg transition could not be settled: {source}")]
    TransitionSettlement {
        /// Why the node-side settlement failed.
        #[source]
        source: Box<ApplyError>,
        /// Execution failure retained when settlement followed a refusal.
        original: Option<Box<Self>>,
    },
    /// Re-reading disconnected bodies for node-owned reconsideration failed
    /// after authoritative rollback had already committed.
    #[error("post-reorg disconnected-body reconsideration failed: {source}")]
    Reconsideration {
        /// Body read/decode failure from the post-reorg pass.
        #[source]
        source: Box<Self>,
        /// Earlier coherent execution outcome, when reconsideration followed a
        /// clean refusal instead of a completed switch.
        original: Option<Box<Self>>,
    },
    /// A nonfatal reorg completed, but the rolled-back state could not be
    /// checkpointed. The chain is coherent at the reached tip and the
    /// disconnect marker remains `RolledBack`; a restart will refuse the data
    /// directory until a later checkpoint publishes this state.
    #[error("disconnect left a checkpoint debt the node could not settle: {source}")]
    CheckpointSettlement {
        /// Checkpoint publication failure.
        #[source]
        source: crate::checkpoint::CheckpointError,
        /// Earlier coherent reorg failure retained when debt settlement also
        /// failed.
        original: Option<Box<Self>>,
    },
    /// The switch needs old-branch history that pruning has already
    /// deleted. Nothing was touched: the retention lease is refused before
    /// the first mutation, and an exact-identity result is impossible
    /// without the bodies. Recovery is a rebuild from retained canonical
    /// data (`RCV-07`), not a retry.
    #[error("reorg requires history at or above height {floor}, which is already pruned: {source}")]
    RetentionUnavailable {
        /// Height the switch pinned.
        floor: u32,
        /// Why the lease was refused.
        #[source]
        source: bitcoin_rs_storage::RetentionError,
    },
}

impl ReorgError {
    /// Whether the execution outcome forbids stable publication and derived
    /// work. Keep this decision with the original typed cause, not a second
    /// disposition that can drift from it.
    pub fn requires_recovery(&self) -> bool {
        match self {
            Self::Fatal(_) | Self::RestorationFailed { .. } | Self::TransitionSettlement { .. } => {
                true
            }
            Self::ConnectFailed { source, .. } => {
                crate::classify_apply_error(source) == crate::WindowApplyDisposition::Fatal
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
            | Self::ConnectBodyLost { .. }
            | Self::NoAppliedTip
            | Self::Invalidation { .. }
            | Self::Reconsideration { .. }
            | Self::CheckpointSettlement { .. }
            | Self::RetentionUnavailable { .. } => false,
        }
    }

    /// Whether node-owned disconnected-transaction reconsideration was
    /// incomplete and any partially collected candidates must be discarded.
    #[must_use]
    pub fn reconsideration_failed(&self) -> bool {
        match self {
            Self::Reconsideration { .. } => true,
            Self::TransitionSettlement {
                original: Some(original),
                ..
            }
            | Self::CheckpointSettlement {
                original: Some(original),
                ..
            }
            | Self::Invalidation { original, .. } => original.reconsideration_failed(),
            _ => false,
        }
    }
}

/// Pins the old-branch bodies a switch will re-read against pruning.
fn retention_lease_for(
    handles: &Chainstate,
    disconnect_nodes: &[(Hash256, u32)],
    connect_nodes: &[(Hash256, u32)],
) -> core::result::Result<Option<bitcoin_rs_storage::RetentionLease>, ReorgError> {
    let Some(floor) = disconnect_nodes
        .iter()
        .chain(connect_nodes)
        .map(|(_, height)| *height)
        .min()
    else {
        return Ok(None);
    };
    handles
        .retention
        .acquire(floor)
        .map(Some)
        .map_err(|source| ReorgError::RetentionUnavailable { floor, source })
}

/// The branch-side facts one reorg attempt needs before it may mutate.
struct PreparedBranches {
    disconnect_nodes: Vec<(Hash256, u32)>,
    connect_nodes: Vec<(Hash256, u32)>,
    connect: Vec<LoadedBranchBody>,
    missing_connect: Option<(Hash256, u32)>,
    retention: Option<bitcoin_rs_storage::RetentionLease>,
}

impl PreparedBranches {
    /// How much of the connect branch the execution pass may attempt.
    fn connect_limit(&self) -> usize {
        if self.missing_connect.is_some() {
            self.connect.len()
        } else {
            self.connect_nodes.len()
        }
    }
}

/// Loads both branch sides of `plan` for one reorg attempt.
fn prepare_branches<F>(
    handles: &Chainstate,
    plan: Option<&ReorgPlan>,
    staged_body: &mut F,
) -> core::result::Result<PreparedBranches, ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    let Some(plan) = plan else {
        return Ok(PreparedBranches {
            disconnect_nodes: Vec::new(),
            connect_nodes: Vec::new(),
            connect: Vec::new(),
            missing_connect: None,
            retention: None,
        });
    };
    let disconnect_nodes = branch_nodes(handles, &plan.disconnect)?;
    let connect_nodes = branch_nodes(handles, &plan.connect)?;
    // The lease must exist before the bodies are first read, so a concurrent
    // prune can never delete what the walk is about to re-read. Only the
    // first connect window is retained; the remainder streams in bounded
    // windows while the authoritative transition is held.
    let retention = retention_lease_for(handles, &disconnect_nodes, &connect_nodes)?;
    let (connect, missing_connect) =
        load_available_branch_prefix(handles, &connect_nodes, staged_body)?;
    if connect.is_empty()
        && let Some((hash, height)) = missing_connect
    {
        return Err(ReorgError::MissingBody { hash, height });
    }
    if !disconnect_nodes.is_empty() {
        preflight_disconnect_bodies(handles, &disconnect_nodes, staged_body)?;
    }
    Ok(PreparedBranches {
        disconnect_nodes,
        connect_nodes,
        connect,
        missing_connect,
        retention,
    })
}

/// Switches the applied chain to `target`.
pub fn switch_to_branch<F, O, S>(
    handles: &Chainstate,
    target: NodeId,
    mut staged_body: F,
    observer: &mut O,
    mut settle: S,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
    O: ReorgObserver + ?Sized,
    S: FnMut(&mut O, core::result::Result<(), ReorgError>) -> core::result::Result<(), ReorgError>,
{
    loop {
        let plan = match current_reorg_plan(handles, target) {
            Ok(Some(plan)) => plan,
            Ok(None) => {
                return settle_reorg_without_transition(handles, observer, Ok(()), &mut settle);
            }
            Err(error) => {
                return settle_reorg_without_transition(handles, observer, Err(error), &mut settle);
            }
        };

        let prepared = match prepare_branches(handles, Some(&plan), &mut staged_body) {
            Ok(prepared) => prepared,
            Err(error) => {
                return settle_reorg_without_transition(handles, observer, Err(error), &mut settle);
            }
        };
        let _retention = &prepared.retention;

        let lock = handles
            .lock_transition()
            .map_err(|source| ReorgError::Unavailable(Box::new(source)));
        let lock = match lock {
            Ok(lock) => lock,
            Err(error) => {
                return settle_reorg_without_transition(handles, observer, Err(error), &mut settle);
            }
        };

        // Preloading is optimistic. Only an identical plan recomputed while the
        // transition lock is held may mutate chainstate.
        let authoritative = match current_reorg_plan(handles, target) {
            Ok(Some(plan)) => plan,
            Ok(None) => {
                let transition = lock.into_transition();
                return settle_reorg_transition(transition, observer, Ok(()), &mut settle);
            }
            Err(error) => {
                let transition = lock.into_transition();
                return settle_reorg_transition(transition, observer, Err(error), &mut settle);
            }
        };
        if plan != authoritative {
            drop(lock);
            continue;
        }

        let transition = lock.into_transition();
        let (progress, outcome) = execute_streamed_plan(
            &transition,
            observer,
            &prepared.disconnect_nodes,
            &prepared.connect_nodes[..prepared.connect_limit()],
            &prepared.connect,
            &mut staged_body,
        );
        // A permanently invalid first target body has committed no rival
        // prefix. Reconnect the old, preflighted branch before releasing this
        // transition so a rejected header branch cannot strand the applied
        // UTXO set at its fork ancestor. Once a rival prefix has committed,
        // the existing coherent-prefix contract remains in force.
        let outcome = match outcome {
            Err(
                original @ ReorgError::ConnectFailed {
                    disposition: crate::WindowApplyDisposition::Permanent,
                    ..
                },
            ) if progress.disconnected > 0 && progress.connected == 0 => {
                match restore_disconnected_branch(
                    &transition,
                    observer,
                    &prepared.disconnect_nodes[..progress.disconnected],
                    &mut staged_body,
                ) {
                    Ok(()) => Err(original),
                    Err(source) => Err(ReorgError::RestorationFailed {
                        source: Box::new(source),
                        original: Box::new(original),
                    }),
                }
            }
            outcome => outcome,
        };
        let outcome = if outcome.as_ref().is_err_and(ReorgError::requires_recovery) {
            outcome
        } else {
            let outcome = match (outcome, prepared.missing_connect) {
                (Ok(()), Some((hash, height))) => Err(ReorgError::MissingBody { hash, height }),
                (outcome, _) => outcome,
            };
            attach_reconsideration(
                outcome,
                revisit_disconnected_blocks(
                    handles,
                    observer,
                    &prepared.disconnect_nodes,
                    progress.disconnected,
                    &mut staged_body,
                ),
            )
        };
        return settle_reorg_transition(transition, observer, outcome, &mut settle);
    }
}

/// How far a loaded branch-switch walk got before it stopped.
#[derive(Clone, Copy)]
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

/// Loads at most one contiguous connect window and names the first missing body.
fn load_available_branch_prefix<F>(
    handles: &Chainstate,
    nodes: &[(Hash256, u32)],
    staged_body: &mut F,
) -> core::result::Result<LoadedBranchPrefix, ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    let window = &nodes[..nodes.len().min(CONNECT_STREAM_WINDOW)];
    let mut loaded = Vec::with_capacity(window.len());
    for &(hash, height) in window {
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
    handles: &Chainstate,
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
    handles: &Chainstate,
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
    if let Some(store) = handles.block_body_store()
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
        deserialize::<Block>(serialized.as_ref()).map_err(|source| ReorgError::BodyDecode {
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
    if !crate::bytes_are_block(serialized.as_ref(), &block) {
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

/// Validates that every disconnect-side body is present, decodable, and
/// hash-correct without retaining any of them.
fn preflight_disconnect_bodies<F>(
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
fn applied_tip_height(handles: &Chainstate) -> u32 {
    handles.applied_tip.load_full().map_or(0, |tip| tip.height)
}

/// Reconnects the fully disconnected old branch, oldest first, under the
/// caller's transition and retention lease. A failed body read or connect is
/// wrapped by `RestorationFailed` at the call site: even if no restoration
/// step committed, the old branch is no longer the applied chain and normal
/// settlement must not publish a stable generation.
fn restore_disconnected_branch<F, O>(
    transition: &ChainTransition<'_>,
    observer: &mut O,
    disconnected: &[(Hash256, u32)],
    staged_body: &mut F,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
    O: ReorgObserver + ?Sized,
{
    let handles = transition.chainstate();
    for (connected, &(hash, height)) in disconnected.iter().rev().enumerate() {
        let body = load_branch_body(handles, hash, height, staged_body)?;
        match transition.connect(&body.block, Some(body.serialized)) {
            Ok(outcome) => observer.connected(&body.block, &outcome),
            Err(source) => {
                return Err(ReorgError::ConnectFailed {
                    disconnected: disconnected.len(),
                    connected,
                    hash,
                    stopped_at: applied_tip_height(handles),
                    disposition: crate::classify_apply_error(&source),
                    source: Box::new(source),
                    invalidated: Vec::new(),
                });
            }
        }
    }
    Ok(())
}

fn execute_streamed_plan<F, O>(
    transition: &ChainTransition<'_>,
    observer: &mut O,
    disconnect_nodes: &[(Hash256, u32)],
    connect_nodes: &[(Hash256, u32)],
    connect_prefix: &[LoadedBranchBody],
    staged_body: &mut F,
) -> (LoadedPlanProgress, core::result::Result<(), ReorgError>)
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
    O: ReorgObserver + ?Sized,
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
                    observer.disconnected(&outcome);
                    progress.disconnected += 1;
                }
                Err(
                    error @ (DisconnectError::Fatal { .. } | DisconnectError::MarkerStuck { .. }),
                ) => {
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

    let outcome = execute_connect_stream(
        transition,
        observer,
        connect_nodes,
        connect_prefix,
        staged_body,
        &mut progress,
    );
    (progress, outcome)
}

fn execute_connect_stream<F, O>(
    transition: &ChainTransition<'_>,
    observer: &mut O,
    connect_nodes: &[(Hash256, u32)],
    connect_prefix: &[LoadedBranchBody],
    staged_body: &mut F,
    progress: &mut LoadedPlanProgress,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
    O: ReorgObserver + ?Sized,
{
    let handles = transition.chainstate();
    for body in connect_prefix {
        connect_loaded_body(transition, observer, progress, body)?;
    }
    for window in connect_nodes[connect_prefix.len()..].chunks(CONNECT_STREAM_WINDOW) {
        let mut bodies = Vec::with_capacity(window.len());
        for (hash, height) in window {
            match load_branch_body(handles, *hash, *height, staged_body) {
                Ok(body) => bodies.push(body),
                Err(source) => {
                    return Err(ReorgError::ConnectBodyLost {
                        disconnected: progress.disconnected,
                        connected: progress.connected,
                        stopped_at: applied_tip_height(handles),
                        source: Box::new(source),
                    });
                }
            }
        }
        for body in &bodies {
            connect_loaded_body(transition, observer, progress, body)?;
        }
    }
    Ok(())
}

fn connect_loaded_body<O>(
    transition: &ChainTransition<'_>,
    observer: &mut O,
    progress: &mut LoadedPlanProgress,
    body: &LoadedBranchBody,
) -> core::result::Result<(), ReorgError>
where
    O: ReorgObserver + ?Sized,
{
    match transition.connect(&body.block, Some(body.serialized.clone())) {
        Ok(outcome) => {
            observer.connected(&body.block, &outcome);
            progress.connected += 1;
            Ok(())
        }
        Err(source) => {
            let disposition = crate::classify_apply_error(&source);
            // A permanently-invalid block must be marked invalid or surfaced:
            // an empty `invalidated` on a failed invalidation would let the
            // next switch retry the same block.
            let invalidated = if disposition == crate::WindowApplyDisposition::Permanent {
                match invalidate_and_republish(transition.chainstate(), body.hash) {
                    Ok(invalidated) => invalidated.into_vec(),
                    Err(invalidation) => {
                        // The tree may be partially marked; republish
                        // whatever tip it still names so `chain_tip` cannot
                        // keep pointing at the invalidated branch, then
                        // surface both failures.
                        let handles = transition.chainstate();
                        let tree = handles.block_tree.read();
                        handles.chain_tip.store(tree.tip());
                        handles.reevaluate_assume_valid_with(&tree);
                        drop(tree);
                        return Err(ReorgError::Invalidation {
                            source: Box::new(ReorgError::from(invalidation)),
                            original: Box::new(ReorgError::ConnectFailed {
                                disconnected: progress.disconnected,
                                connected: progress.connected,
                                hash: body.hash,
                                stopped_at: body.height.saturating_sub(1),
                                source: Box::new(source),
                                disposition,
                                invalidated: Vec::new(),
                            }),
                        });
                    }
                }
            } else {
                Vec::new()
            };
            Err(ReorgError::ConnectFailed {
                disconnected: progress.disconnected,
                connected: progress.connected,
                hash: body.hash,
                stopped_at: body.height.saturating_sub(1),
                source: Box::new(source),
                disposition,
                invalidated,
            })
        }
    }
}

/// Re-reads disconnected bodies oldest-first for node-owned post-reorg work.
fn revisit_disconnected_blocks<F, O>(
    handles: &Chainstate,
    observer: &mut O,
    disconnect_nodes: &[(Hash256, u32)],
    disconnected_count: usize,
    staged_body: &mut F,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
    O: ReorgObserver + ?Sized,
{
    for (hash, block_height) in disconnect_nodes[..disconnected_count].iter().rev() {
        let body = load_branch_body(handles, *hash, *block_height, staged_body)?;
        observer.reconsider_disconnected(&body.block);
    }
    Ok(())
}

fn attach_reconsideration(
    outcome: core::result::Result<(), ReorgError>,
    reconsideration: core::result::Result<(), ReorgError>,
) -> core::result::Result<(), ReorgError> {
    match reconsideration {
        Ok(()) => outcome,
        Err(source) => Err(ReorgError::Reconsideration {
            source: Box::new(source),
            original: outcome.err().map(Box::new),
        }),
    }
}

fn current_reorg_plan(
    handles: &Chainstate,
    target: NodeId,
) -> core::result::Result<Option<ReorgPlan>, ReorgError> {
    let tree = handles.block_tree.read();
    let Some(current) = handles.applied_tip.load_full() else {
        return Err(ReorgError::NoAppliedTip);
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

/// Lets the node settle its follower fence while the authoritative transition
/// is still held, then releases the transition. Expensive checkpoint debt is
/// intentionally not published here; the node owns that after its mempool
/// generation is stable.
fn settle_reorg_transition<O, S>(
    transition: ChainTransition<'_>,
    observer: &mut O,
    outcome: core::result::Result<(), ReorgError>,
    settle: &mut S,
) -> core::result::Result<(), ReorgError>
where
    O: ReorgObserver + ?Sized,
    S: FnMut(&mut O, core::result::Result<(), ReorgError>) -> core::result::Result<(), ReorgError>,
{
    let outcome =
        settle_reorg_without_transition(transition.chainstate(), observer, outcome, settle);
    drop(transition);
    outcome
}

fn settle_reorg_without_transition<O, S>(
    handles: &Chainstate,
    observer: &mut O,
    outcome: core::result::Result<(), ReorgError>,
    settle: &mut S,
) -> core::result::Result<(), ReorgError>
where
    O: ReorgObserver + ?Sized,
    S: FnMut(&mut O, core::result::Result<(), ReorgError>) -> core::result::Result<(), ReorgError>,
{
    let outcome = settle(observer, outcome);
    if outcome.as_ref().is_err_and(ReorgError::requires_recovery) {
        handles.fail_closed_for_recovery();
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin_rs_primitives::Network;
    use bitcoin_rs_utxo::UtxoSet;

    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    struct NoopObserver;

    impl ReorgObserver for NoopObserver {
        fn disconnected(&mut self, _: &DisconnectOutcome) {}

        fn connected(&mut self, _: &Block, _: &ConnectOutcome) {}

        fn reconsider_disconnected(&mut self, _: &Block) {}
    }

    #[test]
    fn fatal_pretransition_settlement_closes_admission() {
        let handles = crate::test_fixtures::handles(Network::Regtest, Arc::new(UtxoSet::new()));
        let shutdown = handles.shutdown_handle();
        let mut observer = NoopObserver;
        let mut settle = |_: &mut NoopObserver, _: core::result::Result<(), ReorgError>| {
            Err(ReorgError::TransitionSettlement {
                source: Box::new(ApplyError::Shutdown),
                original: None,
            })
        };

        let result = settle_reorg_without_transition(&handles, &mut observer, Ok(()), &mut settle);

        assert!(matches!(
            result,
            Err(ReorgError::TransitionSettlement { .. })
        ));
        assert!(shutdown.load(Ordering::Acquire));
        assert!(matches!(
            handles.begin_transition(),
            Err(ApplyError::Shutdown)
        ));
    }
}
