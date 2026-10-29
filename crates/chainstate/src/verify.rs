//! Read-only verification of the newest applied blocks.

use core::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bitcoin_rs_chain::{
    BlockTreeReader, ChainError, LatchReader, NodeId, softfork_state, validate_pow,
};
use bitcoin_rs_consensus::{
    ConsensusError, check_block_body_binding, verify_block::verify_block_non_contextual,
};
use bitcoin_rs_primitives::{Block, DecodeError, Hash256, deserialize};
use bitcoin_rs_storage::{
    BoundedReadError, StorageError,
    block_body::BlockBodyStore,
    pruning::{HistoryLease, HistoryUnavailable},
};
use bitcoin_rs_utxo::contract::{
    UndoCodecError, decode_undo_record_for_block, undo_record_size_limit,
};

use crate::block_spends::MAX_BLOCK_QUERY_BYTES;
use crate::{Chainstate, ChainstateRole};

pub const STARTUP_VERIFY_DEPTH: NonZeroU32 = match NonZeroU32::new(6) {
    Some(depth) => depth,
    None => panic!("the startup verification depth is nonzero"),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckLevel {
    ReadBodies,
    CheckBodies,
    CheckUndo,
    CheckUndoAndCommitments,
}

#[derive(Clone, Debug)]
pub struct VerifyRequest {
    pub level: CheckLevel,
    pub depth: Option<NonZeroU32>,
    pub cancellation: Option<LatchReader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    Passed { blocks: u32 },
    SkippedNoBlockData { height: u32 },
}

#[derive(Debug, thiserror::Error)]
pub enum BodyDecodeError {
    #[error(transparent)]
    Malformed(DecodeError),
    #[error("header hashes to {found}")]
    HashMismatch { found: Hash256 },
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("block {hash} at height {height} has no stored body")]
    BodyMissing { height: u32, hash: Hash256 },
    #[error("reading the body of block {hash} at height {height} failed: {source}")]
    BodyRead {
        height: u32,
        hash: Hash256,
        #[source]
        source: BoundedReadError,
    },
    /// The stored body frame is malformed or truncated.
    ///
    /// Corruption the verifier observes is damage, never a missing body and never a
    /// skip: a prune pass deletes rows atomically and never leaves corrupt frames
    /// behind.
    #[error("body frame of block {hash} at height {height} is corrupt: {evidence}")]
    BodyCorrupt {
        height: u32,
        hash: Hash256,
        evidence: &'static str,
    },
    #[error("body of block {hash} at height {height} does not decode: {source}")]
    BodyDecode {
        height: u32,
        hash: Hash256,
        #[source]
        source: BodyDecodeError,
    },
    #[error("block {hash} at height {height} fails its proof-of-work check: {source}")]
    ProofOfWork {
        height: u32,
        hash: Hash256,
        #[source]
        source: Box<ChainError>,
    },
    #[error("body of block {hash} at height {height} does not match its header: {source}")]
    Binding {
        height: u32,
        hash: Hash256,
        #[source]
        source: ConsensusError,
    },
    #[error("block {hash} at height {height} has no stored undo record")]
    UndoMissing { height: u32, hash: Hash256 },
    #[error("reading the undo record of block {hash} at height {height} failed: {source}")]
    UndoRead {
        height: u32,
        hash: Hash256,
        #[source]
        source: BoundedReadError,
    },
    /// The chainstate closed for recovery: verification refuses to declare anything
    /// verified from a chain that can no longer admit mutations.
    ///
    /// This names no block; it is fail-closed admission state, not damage.
    #[error("chainstate is closed for recovery")]
    ClosedForRecovery,
    #[error("block verification was interrupted")]
    Interrupted,
    #[error("undo record of block {hash} at height {height} does not decode: {source}")]
    UndoDecode {
        height: u32,
        hash: Hash256,
        #[source]
        source: Box<UndoCodecError>,
    },
}

/// INVARIANT: no history is read unpinned, and a read that finds nothing
/// after the owner withdrew the pin is `SkippedNoBlockData`, never damage.
///
/// The pin is also checked at every progress boundary and before reporting
/// success, so a withdrawal the walk already passed still refuses `Passed`.
pub fn verify_recent_blocks(
    chainstate: &Chainstate,
    request: VerifyRequest,
) -> Result<VerifyOutcome, VerifyError> {
    if request
        .cancellation
        .as_ref()
        .is_some_and(LatchReader::is_triggered)
    {
        return Err(VerifyError::Interrupted);
    }
    if chainstate.is_closed_for_recovery() {
        return Err(VerifyError::ClosedForRecovery);
    }
    let Some(tip) = chainstate
        .applied_tip_snapshot()
        .filter(|tip| tip.height > 0)
    else {
        return Ok(VerifyOutcome::Passed { blocks: 0 });
    };
    let Some(store) = chainstate.block_body_store_handle() else {
        return Ok(VerifyOutcome::SkippedNoBlockData { height: tip.height });
    };
    let requested = request
        .depth
        .map_or(1, |depth| tip.height.saturating_sub(depth.get() - 1))
        .max(1);
    let (lease, start) = match pin_window(chainstate, requested, tip.height) {
        Ok(pinned) => pinned,
        Err(height) => return Ok(VerifyOutcome::SkippedNoBlockData { height }),
    };
    let walk = Walk {
        chainstate,
        store,
        lease,
        level: request.level,
        cancellation: request.cancellation,
    };
    match walk.run(tip.tip_id, tip.hash, tip.height, start) {
        Ok(_) if start > requested => Ok(VerifyOutcome::SkippedNoBlockData {
            height: start.saturating_sub(1),
        }),
        Ok(blocks) => Ok(VerifyOutcome::Passed { blocks }),
        Err(Stop::Skipped { height }) => Ok(VerifyOutcome::SkippedNoBlockData { height }),
        Err(Stop::Interrupted) => Err(VerifyError::Interrupted),
        Err(Stop::Failed(error)) => Err(error),
    }
}

fn pin_window(
    chainstate: &Chainstate,
    requested: u32,
    tip_height: u32,
) -> Result<(HistoryLease, u32), u32> {
    let role_floor = match chainstate.role() {
        ChainstateRole::AssumedActive { base_height, .. } => base_height.saturating_add(1),
        ChainstateRole::Ordinary | ChainstateRole::Historical { .. } => 0,
    };
    let mut start = requested.max(role_floor);
    for _ in 0..PIN_ATTEMPTS {
        if start > tip_height {
            break;
        }
        match chainstate.history.request_history(start) {
            Ok(lease) => return Ok((lease, start)),
            Err(HistoryUnavailable::Pruned { below } | HistoryUnavailable::Reserved { below })
                if below > start =>
            {
                start = below;
            }
            Err(_) => break,
        }
    }
    Err(tip_height)
}

const PIN_ATTEMPTS: usize = 3;

enum Stop {
    Skipped { height: u32 },
    Interrupted,
    Failed(VerifyError),
}

impl From<VerifyError> for Stop {
    fn from(error: VerifyError) -> Self {
        Self::Failed(error)
    }
}

struct Ancestor {
    hash: Hash256,
    parent: NodeId,
    prev_hash: Hash256,
    segwit_active: bool,
}

struct Walk<'a> {
    chainstate: &'a Chainstate,
    store: Arc<dyn BlockBodyStore>,
    lease: HistoryLease,
    level: CheckLevel,
    cancellation: Option<LatchReader>,
}

impl Walk<'_> {
    fn run(
        &self,
        tip_id: NodeId,
        tip_hash: Hash256,
        tip_height: u32,
        start: u32,
    ) -> Result<u32, Stop> {
        let tree = self.chainstate.block_tree_reader();
        let mut next = (tip_id, tip_hash);
        let mut checked = 0_u32;
        for height in (start..=tip_height).rev() {
            self.poll_boundaries(height)?;
            let ancestor = self.locate(&tree, next.0, height, next.1)?;
            next = (ancestor.parent, ancestor.prev_hash);
            self.check(height, &ancestor)?;
            checked = checked.saturating_add(1);
        }
        self.poll_boundaries(tip_height)?;
        Ok(checked)
    }

    /// One boundary poll: cancellation first, then fail-closed recovery,
    /// then process shutdown, then the bounded history pin. A withdrawn pin
    /// is skipped even when the rows it covered are still readable.
    fn poll_boundaries(&self, height: u32) -> Result<(), Stop> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(LatchReader::is_triggered)
        {
            return Err(Stop::Interrupted);
        }
        if self.chainstate.is_closed_for_recovery() {
            return Err(Stop::Failed(VerifyError::ClosedForRecovery));
        }
        if self.chainstate.shutdown.load(Ordering::Acquire) {
            return Err(Stop::Skipped { height });
        }
        if self.lease.floor().is_none() {
            return Err(Stop::Skipped { height });
        }
        Ok(())
    }

    fn locate(
        &self,
        tree: &BlockTreeReader,
        id: NodeId,
        height: u32,
        hash: Hash256,
    ) -> Result<Ancestor, VerifyError> {
        let guard = tree.read();
        let Some(node) = guard
            .node(id)
            .ok()
            .filter(|node| node.height == height && node.hash == hash)
        else {
            return Err(VerifyError::BodyMissing { height, hash });
        };
        let prev_hash = node.header.prev_blockhash.0;
        let Some(parent) = node.parent else {
            return Err(VerifyError::BodyMissing {
                height: height.saturating_sub(1),
                hash: prev_hash,
            });
        };
        let segwit_active = self.level >= CheckLevel::CheckUndoAndCommitments
            && softfork_state(&guard, self.chainstate.network, Some(parent), height).segwit_active;
        Ok(Ancestor {
            hash,
            parent,
            prev_hash,
            segwit_active,
        })
    }

    fn check(&self, height: u32, ancestor: &Ancestor) -> Result<(), Stop> {
        let block = self.read_block(height, ancestor.hash)?;
        if self.level >= CheckLevel::CheckBodies {
            check_body(self.chainstate, &block, height, ancestor.hash)?;
        }
        if self.level >= CheckLevel::CheckUndo {
            self.check_undo(&block, height, ancestor.hash)?;
        }
        if self.level >= CheckLevel::CheckUndoAndCommitments {
            check_binding(&block, height, ancestor)?;
        }
        Ok(())
    }

    fn read_block(&self, height: u32, hash: Hash256) -> Result<Block, Stop> {
        let bytes = match self.store.load_block_body_for_verification_bounded(
            height,
            hash,
            MAX_BLOCK_QUERY_BYTES,
        ) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Err(self.absent(height, VerifyError::BodyMissing { height, hash })),
            Err(BoundedReadError::Storage(StorageError::CorruptBlockFrame(evidence))) => {
                return Err(Stop::Failed(VerifyError::BodyCorrupt {
                    height,
                    hash,
                    evidence,
                }));
            }
            Err(source) => {
                return Err(Stop::Failed(VerifyError::BodyRead {
                    height,
                    hash,
                    source,
                }));
            }
        };
        Ok(decode_body(&bytes, height, hash)?)
    }

    fn check_undo(&self, block: &Block, height: u32, hash: Hash256) -> Result<(), Stop> {
        let record = self.load_undo(block, height, hash)?;
        decode_undo_record_for_block(&record, block)
            .map(drop)
            .map_err(|source| {
                Stop::Failed(VerifyError::UndoDecode {
                    height,
                    hash,
                    source: Box::new(source),
                })
            })
    }

    fn load_undo(&self, block: &Block, height: u32, hash: Hash256) -> Result<Vec<u8>, Stop> {
        match self.chainstate.undo_store.load_undo_bounded(
            height,
            hash,
            undo_record_size_limit(block, bitcoin_rs_script::MAX_SCRIPT_SIZE),
        ) {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(self.absent(height, VerifyError::UndoMissing { height, hash })),
            Err(source) => Err(Stop::Failed(VerifyError::UndoRead {
                height,
                hash,
                source,
            })),
        }
    }

    fn absent(&self, height: u32, damage: VerifyError) -> Stop {
        if self.lease.floor().is_some() {
            Stop::Failed(damage)
        } else {
            Stop::Skipped { height }
        }
    }
}

fn decode_body(bytes: &[u8], height: u32, hash: Hash256) -> Result<Block, VerifyError> {
    let refused = |source| VerifyError::BodyDecode {
        height,
        hash,
        source,
    };
    let block: Block =
        deserialize(bytes).map_err(|source| refused(BodyDecodeError::Malformed(source)))?;
    let found = block.block_hash().0;
    if found != hash {
        return Err(refused(BodyDecodeError::HashMismatch { found }));
    }
    Ok(block)
}

fn check_body(
    chainstate: &Chainstate,
    block: &Block,
    height: u32,
    hash: Hash256,
) -> Result<(), VerifyError> {
    validate_pow(&block.header, hash, chainstate.network).map_err(|source| {
        VerifyError::ProofOfWork {
            height,
            hash,
            source: Box::new(source),
        }
    })?;
    verify_block_non_contextual(block).map_err(|source| VerifyError::Binding {
        height,
        hash,
        source,
    })
}

fn check_binding(block: &Block, height: u32, ancestor: &Ancestor) -> Result<(), VerifyError> {
    let hash = ancestor.hash;
    check_block_body_binding(block, ancestor.segwit_active).map_err(|source| VerifyError::Binding {
        height,
        hash,
        source,
    })
}

#[cfg(test)]
mod tests;
