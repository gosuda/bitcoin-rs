//! Switching the applied chain from one tip to another.

use crate::{
    ApplyError, ChainTransition, Chainstate, ConnectOutcome, DisconnectError, DisconnectOutcome,
};
use bitcoin_rs_chain::{InvalidationOutcome, NodeId, ReorgPlan, plan_reorg};
use bitcoin_rs_primitives::{Block, BlockPayload, DecodeError, Hash256};
use bitcoin_rs_storage::StorageError;

/// Maximum number of disconnect-side block bodies held in memory at once
/// during the streaming execution pass.
const DISCONNECT_STREAM_WINDOW: usize = 8;
const CONNECT_STREAM_WINDOW: usize = DISCONNECT_STREAM_WINDOW;

pub trait ReorgObserver {
    fn disconnected(&mut self, outcome: &DisconnectOutcome);

    fn connected(&mut self, block: &Block, outcome: &ConnectOutcome);

    fn reconsider_disconnected(&mut self, block: &Block);
}

pub fn invalidate_block<O, S>(
    handles: &Chainstate,
    observer: &mut O,
    hash: Hash256,
    mut settle: S,
) -> core::result::Result<InvalidationOutcome, ReorgError>
where
    O: ReorgObserver + ?Sized,
    S: FnMut(&mut O, core::result::Result<(), ReorgError>) -> core::result::Result<(), ReorgError>,
{
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
            .map(|()| InvalidationOutcome::default());
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
            .map(|()| InvalidationOutcome::default());
        }
    };
    let mut invalidated = InvalidationOutcome::default();
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

#[derive(Debug, thiserror::Error)]
pub(super) enum InvalidationError {
    #[error("unknown block {0}")]
    UnknownBlock(Hash256),
    #[error("invalidation left no valid chain tip")]
    NoValidTip,
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

pub(super) fn invalidate_and_republish(
    handles: &Chainstate,
    hash: Hash256,
) -> core::result::Result<InvalidationOutcome, InvalidationError> {
    let mut tree = handles.block_tree.write();
    let root = tree
        .lookup(hash)
        .ok_or(InvalidationError::UnknownBlock(hash))?;
    let invalidated = tree
        .invalidate_subtree(root)
        .map_err(InvalidationError::Plan)?;
    let tip = tree.tip().ok_or(InvalidationError::NoValidTip)?;
    handles.publish_chain_tip(Some(tip), &tree);
    Ok(invalidated)
}

#[derive(Debug, thiserror::Error)]
pub enum ReorgError {
    #[error("unknown block {0}")]
    UnknownBlock(Hash256),
    #[error("cannot invalidate the genesis block")]
    CannotInvalidateGenesis,
    #[error("invalidation left no valid chain tip")]
    NoValidTip,
    #[error("no applied tip; the chain cannot be switched before genesis is applied")]
    NoAppliedTip,
    #[error("reorg planning failed: {0}")]
    Plan(#[source] bitcoin_rs_chain::ChainError),
    #[error("no stored body for block {hash} at height {height}")]
    MissingBody { hash: Hash256, height: u32 },
    #[error("failed to read body for block {hash} at height {height}: {source}")]
    BodyStore {
        hash: Hash256,
        height: u32,
        #[source]
        source: StorageError,
    },
    #[error("failed to decode body for block {hash} at height {height}: {source}")]
    BodyDecode {
        hash: Hash256,
        height: u32,
        #[source]
        source: DecodeError,
    },
    #[error("body hash {actual} does not match planned block {expected} at height {height}")]
    BodyHashMismatch {
        expected: Hash256,
        actual: Hash256,
        height: u32,
    },
    #[error("preserved bytes do not match staged block {hash} at height {height}")]
    BodyBytesMismatch { hash: Hash256, height: u32 },
    #[error("reorg unavailable before mutation: {0}")]
    Unavailable(#[source] Box<ApplyError>),
    #[error("reorg stopped at height {stopped_at}: {source}")]
    Refused {
        disconnected: usize,
        stopped_at: u32,
        #[source]
        source: Box<DisconnectError>,
    },
    #[error(
        "reorg stopped at height {stopped_at} after {disconnected} disconnects: body lost mid-rollback: {source}"
    )]
    DisconnectBodyLost {
        disconnected: usize,
        stopped_at: u32,
        #[source]
        source: Box<Self>,
    },
    #[error(
        "reorg stopped at height {stopped_at} after {disconnected} disconnects and {connected} connects: body lost mid-switch: {source}"
    )]
    ConnectBodyLost {
        disconnected: usize,
        connected: usize,
        stopped_at: u32,
        #[source]
        source: Box<Self>,
    },
    #[error(
        "reorg target connect failed after reaching height {stopped_at} at block {hash}: {source}"
    )]
    ConnectFailed {
        disconnected: usize,
        connected: usize,
        hash: Hash256,
        stopped_at: u32,
        #[source]
        source: Box<ApplyError>,
        disposition: crate::WindowApplyDisposition,
        invalidated: Box<[Hash256]>,
        demoted_tip: Option<Hash256>,
    },
    #[error("post-connect invalidation failed: {source}; original: {original}")]
    Invalidation {
        #[source]
        source: Box<Self>,
        original: Box<Self>,
    },
    #[error(
        "reorg could not restore the previously applied branch: {source}; original: {original}"
    )]
    RestorationFailed {
        #[source]
        source: Box<Self>,
        original: Box<Self>,
    },
    #[error("reorg left the chainstate inconsistent: {0}")]
    Fatal(#[source] Box<DisconnectError>),
    #[error("reorg transition could not be settled: {source}")]
    TransitionSettlement {
        #[source]
        source: Box<ApplyError>,
        original: Option<Box<Self>>,
    },
    #[error("post-reorg disconnected-body reconsideration failed: {source}")]
    Reconsideration {
        #[source]
        source: Box<Self>,
        original: Option<Box<Self>>,
    },
    #[error("disconnect left a checkpoint debt the node could not settle: {source}")]
    CheckpointSettlement {
        #[source]
        source: crate::checkpoint::CheckpointError,
        original: Option<Box<Self>>,
    },
    #[error("reorg requires history at or above height {floor}, which is already pruned: {source}")]
    RetentionUnavailable {
        floor: u32,
        #[source]
        source: bitcoin_rs_storage::RetentionError,
    },
}

impl ReorgError {
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

struct PreparedBranches {
    disconnect_nodes: Vec<(Hash256, u32)>,
    connect_nodes: Vec<(Hash256, u32)>,
    connect: Vec<LoadedBranchBody>,
    missing_connect: Option<(Hash256, u32)>,
    retention: Option<bitcoin_rs_storage::RetentionLease>,
}

impl PreparedBranches {
    fn connect_limit(&self) -> usize {
        if self.missing_connect.is_some() {
            self.connect.len()
        } else {
            self.connect_nodes.len()
        }
    }
}

fn prepare_branches<F>(
    handles: &Chainstate,
    plan: Option<&ReorgPlan>,
    staged_body: &mut F,
) -> core::result::Result<PreparedBranches, ReorgError>
where
    F: FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
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

pub fn switch_to_branch<F, O, S>(
    handles: &Chainstate,
    target: NodeId,
    mut staged_body: F,
    observer: &mut O,
    mut settle: S,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
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

#[derive(Clone, Copy)]
struct LoadedPlanProgress {
    disconnected: usize,
    connected: usize,
}

struct LoadedBranchBody {
    hash: Hash256,
    payload: BlockPayload,
    height: u32,
}

type LoadedBranchPrefix = (Vec<LoadedBranchBody>, Option<(Hash256, u32)>);

fn load_available_branch_prefix<F>(
    handles: &Chainstate,
    nodes: &[(Hash256, u32)],
    staged_body: &mut F,
) -> core::result::Result<LoadedBranchPrefix, ReorgError>
where
    F: FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
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
    F: FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
{
    if let Some(payload) = staged_body(hash) {
        return validate_branch_body(hash, height, payload);
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
    let payload = BlockPayload::from_raw(serialized).map_err(|source| ReorgError::BodyDecode {
        hash,
        height,
        source,
    })?;
    validate_branch_body(hash, height, payload)
}

fn validate_branch_body(
    expected: Hash256,
    height: u32,
    payload: BlockPayload,
) -> core::result::Result<LoadedBranchBody, ReorgError> {
    let actual = payload.block().block_hash().0;
    if actual != expected {
        return Err(ReorgError::BodyHashMismatch {
            expected,
            actual,
            height,
        });
    }
    if !crate::bytes_are_block(payload.bytes().as_ref(), payload.block()) {
        return Err(ReorgError::BodyBytesMismatch {
            hash: expected,
            height,
        });
    }
    Ok(LoadedBranchBody {
        hash: expected,
        payload,
        height,
    })
}

fn preflight_disconnect_bodies<F>(
    handles: &Chainstate,
    nodes: &[(Hash256, u32)],
    staged_body: &mut F,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
{
    for (hash, height) in nodes {
        load_branch_body(handles, *hash, *height, staged_body)?;
    }
    Ok(())
}

fn applied_tip_height(handles: &Chainstate) -> u32 {
    handles.applied_tip.load_full().map_or(0, |tip| tip.height)
}

fn restore_disconnected_branch<F, O>(
    transition: &ChainTransition<'_>,
    observer: &mut O,
    disconnected: &[(Hash256, u32)],
    staged_body: &mut F,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
    O: ReorgObserver + ?Sized,
{
    let handles = transition.chainstate();
    for (connected, &(hash, height)) in disconnected.iter().rev().enumerate() {
        let body = load_branch_body(handles, hash, height, staged_body)?;
        match transition.connect(&body.payload) {
            Ok(outcome) => observer.connected(body.payload.block(), &outcome),
            Err(source) => {
                return Err(ReorgError::ConnectFailed {
                    disconnected: disconnected.len(),
                    connected,
                    hash,
                    stopped_at: applied_tip_height(handles),
                    disposition: crate::classify_apply_error(&source),
                    source: Box::new(source),
                    invalidated: Box::default(),
                    demoted_tip: None,
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
    F: FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
    O: ReorgObserver + ?Sized,
{
    let handles = transition.chainstate();
    let mut progress = LoadedPlanProgress {
        disconnected: 0,
        connected: 0,
    };

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
            match transition.disconnect(body.payload.block()) {
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
    F: FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
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
    match transition.connect(&body.payload) {
        Ok(outcome) => {
            observer.connected(body.payload.block(), &outcome);
            progress.connected += 1;
            Ok(())
        }
        Err(source) => {
            let disposition = crate::classify_apply_error(&source);
            let InvalidationOutcome {
                invalid: invalidated,
                demoted_tip,
            } = if disposition == crate::WindowApplyDisposition::Permanent {
                match invalidate_and_republish(transition.chainstate(), body.hash) {
                    Ok(outcome) => outcome,
                    Err(invalidation) => {
                        let handles = transition.chainstate();
                        let tree = handles.block_tree.read();
                        handles.publish_chain_tip(tree.tip(), &tree);
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
                                invalidated: Box::default(),
                                demoted_tip: None,
                            }),
                        });
                    }
                }
            } else {
                InvalidationOutcome::default()
            };
            Err(ReorgError::ConnectFailed {
                disconnected: progress.disconnected,
                connected: progress.connected,
                hash: body.hash,
                stopped_at: body.height.saturating_sub(1),
                source: Box::new(source),
                disposition,
                invalidated: invalidated.into_boxed_slice(),
                demoted_tip,
            })
        }
    }
}

fn revisit_disconnected_blocks<F, O>(
    handles: &Chainstate,
    observer: &mut O,
    disconnect_nodes: &[(Hash256, u32)],
    disconnected_count: usize,
    staged_body: &mut F,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
    O: ReorgObserver + ?Sized,
{
    for (hash, block_height) in disconnect_nodes[..disconnected_count].iter().rev() {
        let body = load_branch_body(handles, *hash, *block_height, staged_body)?;
        observer.reconsider_disconnected(body.payload.block());
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
