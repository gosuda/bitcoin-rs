//! Switching the applied chain from one tip to another.
//!
//! [`plan_reorg`] says which blocks to disconnect and which to connect;
//! [`ChainTransition::disconnect`] rolls one back and
//! [`ChainTransition::connect`] applies one. This joins them.
//! Without it the node follows the chain forward and cannot leave a branch that
//! loses, which is the difference between a chain follower and a full node.

use crate::ApplyError;
use crate::ChainTransition;
use crate::Chainstate;
use crate::ConnectOutcome;
use crate::DisconnectError;
use crate::DisconnectOutcome;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::ReorgPlan;
use bitcoin_rs_chain::plan_reorg;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::DecodeError;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::StorageError;

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
const CONNECT_STREAM_WINDOW: usize = DISCONNECT_STREAM_WINDOW;

/// Node-owned work that follows committed reorg steps.
///
/// Chainstate invokes this only after each authoritative mutation commits. The
/// implementation may wake indexes, evict or reconsider mempool entries, or
/// release staged bodies, but it cannot influence chainstate correctness.
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
///
/// On success returns every hash `invalidate_subtree` marked `Invalid`, so the
/// caller can purge staged and download state after the transition settles.
#[allow(clippy::too_many_lines)]
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
    let mut invalidated = Vec::new();
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
    settle_reorg_transition(transition, observer, outcome, &mut settle)
        .map(|()| invalidated.into_boxed_slice())
}

/// Marks `hash`'s subtree invalid under the tree write lock and republishes
/// the best remaining tip, keeping `chain_tip` and the assume-valid gate in
/// sync with the tree. Lookup miss, tree inconsistency, and the absence of a
/// valid tip surface as `UnknownBlock`/`Plan`/`NoValidTip` rather than an
/// empty result so callers cannot mistake a failed invalidation for an
/// empty subtree.
fn invalidate_and_republish(
    handles: &Chainstate,
    hash: Hash256,
) -> core::result::Result<Vec<Hash256>, ReorgError> {
    let mut tree = handles.block_tree.write();
    let root = tree.lookup(hash).ok_or(ReorgError::UnknownBlock(hash))?;
    let invalidated = tree.invalidate_subtree(root).map_err(ReorgError::Plan)?;
    let tip = tree.tip().ok_or(ReorgError::NoValidTip)?;
    handles.chain_tip.store(Some(tip));
    handles.reevaluate_assume_valid_with(&tree);
    Ok(invalidated)
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
    /// No applied tip exists yet.
    ///
    /// The chain cannot be switched before genesis is applied. Nothing was
    /// touched.
    #[error("no applied tip; the chain cannot be switched before genesis is applied")]
    NoAppliedTip,
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
    /// A target-branch body became unreadable after the switch started.
    /// Everything counted committed fully; the chain is coherent at `stopped_at`.
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
    /// A connect failed after some of the new branch was applied.
    ///
    /// Every block before this one committed fully. A refusal before the UTXO
    /// commit leaves a consistent prefix of the target branch; a
    /// [`ApplyError::UtxoCommit`] or durable-head failure may leave partial
    /// or unconfirmed state and requires recovery with admission closed. The switch is abandoned
    /// rather than rolled back — undoing the prefix means disconnecting blocks that just
    /// applied, which can fail Fatal and turn a recoverable stop into an
    /// unrecoverable one. A later switch can continue from a coherent prefix;
    /// a failed UTXO or durable-head commit must first recover its authoritative state.
    ///
    /// When the failure is permanently branch-invalid (`PoW`, `nBits`, or
    /// non-mutation consensus),
    /// the failed block's subtree is invalidated while the chain transition is
    /// still held, and `invalidated` carries every hash that was marked
    /// `Invalid` so the caller can purge staged/download state after releasing
    /// the transition. Body mutation and operational failures leave
    /// `invalidated` empty; `disposition` distinguishes their retry handling.
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
    ///
    /// The tree may be partially marked, so the tip was republished from
    /// whatever it still names before this surfaced. The causal connect
    /// error and committed progress stay in `original` so callers keep both
    /// signals.
    #[error("post-connect invalidation failed: {source}; original: {original}")]
    Invalidation {
        /// `UnknownBlock`/`Plan`/`NoValidTip` from the invalidation attempt.
        #[source]
        source: Box<Self>,
        /// The connect failure that triggered the invalidation.
        original: Box<Self>,
    },
    /// A disconnect died partway. The chainstate is torn.
    ///
    /// Propagated immediately and never continued past: applying the new branch
    /// on top of a half-rolled-back state would build on a chain the node
    /// cannot describe. The in-flight marker is already durable, so a restart
    /// refuses rather than serving it.
    #[error("reorg left the chainstate inconsistent: {0}")]
    Fatal(#[source] Box<DisconnectError>),
    /// Node-side settlement failed after the authoritative chain walk.
    /// Admission is permanently closed and shutdown is requested.
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
        source: crate::CheckpointError,
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
            Self::Fatal(_) | Self::TransitionSettlement { .. } => true,
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
///
/// The floor is the fork ancestor: every disconnect-side body sits at or
/// above it, and every connect-side body sits above the ancestor too, so
/// one floor covers both walks. The caller holds the lease until the
/// attempt settles — completed, refused, or failed — and the guard releases
/// it exactly once on every exit path.
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
        .retention_handle()
        .acquire(floor)
        .map(Some)
        .map_err(|source| ReorgError::RetentionUnavailable { floor, source })
}

/// The branch-side facts one reorg attempt needs before it may mutate.
///
/// `disconnect_nodes` and `connect_nodes` are the plan's hashes and heights;
/// `connect` is the first contiguous window of available connect bodies;
/// `missing_connect` names the first absent connect body after that prefix;
/// `retention` pins both branches' bodies against pruning until the attempt
/// settles.
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
///
/// A `None` plan yields empty branches. The retention lease is taken before
/// the first body read, so a concurrent prune can never delete what the walk
/// is about to re-read. A first-block connect gap fails before the
/// disconnect-side preflight runs.
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
///
/// Disconnects back to the common ancestor, then applies the target branch
/// forward. Both walks take the plan's order: `disconnect` runs from the old
/// tip downward and `connect` from the ancestor's child upward. The observer
/// sees each committed step while the transition is still held.
///
/// # Errors
///
/// Every outcome other than reaching `target` is a [`ReorgError`] variant
/// naming how far the chain moved, because "it failed" does not tell a caller
/// whether the node is fine, degraded, or unusable.
#[allow(clippy::too_many_lines)]
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
///
/// This is the first of two passes: it discovers a missing or corrupt
/// old-branch body before the rollback starts, preserving the "nothing was
/// touched" failure model for body-load errors. The execution pass
/// ([`execute_streamed_plan`]) re-reads each body in a bounded window;
/// storage can fail between the two passes, and that mid-rollback failure is
/// reported as [`ReorgError::DisconnectBodyLost`].
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
                    Ok(invalidated) => invalidated,
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
                            source: Box::new(invalidation),
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
///
/// The authoritative owner retains no whole-branch body clone: each body is
/// decoded, observed, and dropped before the next one is loaded.
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
    let handles = transition.chainstate();
    let outcome = settle(observer, outcome);
    if outcome.as_ref().is_err_and(ReorgError::requires_recovery) {
        handles.fail_closed_for_recovery();
        drop(transition);
        return outcome;
    }
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
    use arc_swap::ArcSwapOption;
    use bitcoin_rs_chain::BlockTree;
    use bitcoin_rs_primitives::Network;
    use bitcoin_rs_utxo::UtxoSet;
    use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
    use parking_lot::RwLock;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    struct NoopObserver;

    impl ReorgObserver for NoopObserver {
        fn disconnected(&mut self, _: &DisconnectOutcome) {}

        fn connected(&mut self, _: &Block, _: &ConnectOutcome) {}

        fn reconsider_disconnected(&mut self, _: &Block) {}
    }

    fn chainstate() -> Chainstate {
        Chainstate::new(
            Network::Regtest,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(BlockTree::new())),
            Arc::new(UtxoSet::new()),
            Arc::new(CoinStatsListener::new(CoinStats::default())),
            Arc::new(crate::events::ChainEventPublisher::detached(0)),
        )
    }

    #[test]
    fn fatal_pretransition_settlement_closes_admission() {
        let handles = chainstate();
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
