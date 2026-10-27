//! Read-only verification of the newest applied blocks.
//!
//! One owner serves the `verifychain` RPC and the startup check. The walk
//! follows parent links from the applied tip, never mutates chain state, and
//! holds a history lease for the whole walk so a concurrent prune pass cannot
//! delete rows it is about to read. The lease is a bounded optional pin, not
//! an atomic exclusion around IO: its liveness is re-checked at every
//! progress boundary, and a withdrawn pin ends the walk as
//! [`VerifyOutcome::SkippedNoBlockData`] even when the rows are still
//! readable. A cancelled request ends as [`VerifyError::Interrupted`]; a
//! chainstate closed for recovery is fail-closed as
//! [`VerifyError::ClosedForRecovery`], including an empty or genesis-only
//! chain. Data the node never kept or intentionally no longer keeps ends the
//! walk as [`VerifyOutcome::SkippedNoBlockData`]; data that should exist and
//! does not, or does not check out, is a typed [`VerifyError`]. The RPC level
//! mapping stops at [`CheckLevel::CheckUndo`] with Core's context-free scope;
//! startup selects [`CheckLevel::CheckUndoAndCommitments`], which additionally
//! enforces header-body binding on data at rest.

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

/// How many of the newest applied blocks startup verifies.
pub const STARTUP_VERIFY_DEPTH: NonZeroU32 = match NonZeroU32::new(6) {
    Some(depth) => depth,
    None => panic!("the startup verification depth is nonzero"),
};

/// How much of each block the verifier checks. Every level includes the
/// checks of the levels before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckLevel {
    /// Read each stored body, decode it, and confirm it is the block the
    /// block tree names.
    ReadBodies,
    /// Also check the header's proof of work and the consensus-owned
    /// context-free body rules: coinbase placement, the stripped block size,
    /// transaction shape and value, and aggregate legacy sigop cost. This is
    /// Core's `CheckBlock` set minus witness commitments, full witness
    /// weight, finality, and UTXO/script execution.
    CheckBodies,
    /// Also read each undo record and decode it against its block.
    CheckUndo,
    /// Also check header-body binding, including the witness commitment, via
    /// the consensus-owned check. This is stronger than Core's level 1 and is
    /// not reachable from the RPC level mapping; startup uses it so data at
    /// rest keeps the commitment guarantee the connect path enforces on new
    /// blocks.
    CheckUndoAndCommitments,
}

/// One verification request.
#[derive(Clone, Debug)]
pub struct VerifyRequest {
    /// The checks applied to every block in the window.
    pub level: CheckLevel,
    /// How many blocks to check, counted back from the applied tip; `None`
    /// checks every block above genesis.
    pub depth: Option<NonZeroU32>,
    /// The caller's cancellation latch, observed during the walk and before
    /// reporting success; `None` when the caller cannot cancel (startup).
    /// A triggered latch ends the walk as [`VerifyError::Interrupted`],
    /// never as damage and never as unavailable history.
    pub cancellation: Option<LatchReader>,
}

/// How a verification that found no damage ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Every block in the window was checked and passed.
    Passed {
        /// Number of blocks checked. Genesis, which has no parent, is never
        /// counted.
        blocks: u32,
    },
    /// The window reaches data this node does not hold: history a prune pass
    /// deleted or claimed, history below an assumed-valid snapshot base, a
    /// store without block bodies, or a pin the retention owner withdrew.
    /// Every block above `height` that the node still holds passed.
    SkippedNoBlockData {
        /// The highest height whose data was unavailable.
        height: u32,
    },
}

/// Why a stored body does not decode to the block the tree names.
#[derive(Debug, thiserror::Error)]
pub enum BodyDecodeError {
    /// The bytes are not one complete consensus-encoded block.
    #[error(transparent)]
    Malformed(DecodeError),
    /// The bytes decode to a block whose header hashes to something else.
    #[error("header hashes to {found}")]
    HashMismatch {
        /// The hash the decoded header actually has.
        found: Hash256,
    },
}

/// Damage found inside the verified window. Each variant names the block.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The block has no stored body, or its header is absent from the block
    /// tree although the chain above it names it.
    #[error("block {hash} at height {height} has no stored body")]
    BodyMissing {
        /// Block height.
        height: u32,
        /// Block hash the chain names.
        hash: Hash256,
    },
    /// The body store failed to read the block.
    #[error("reading the body of block {hash} at height {height} failed: {source}")]
    BodyRead {
        /// Block height.
        height: u32,
        /// Block hash the chain names.
        hash: Hash256,
        /// The storage failure.
        #[source]
        source: BoundedReadError,
    },
    /// The stored body frame is malformed or truncated. Corruption the
    /// verifier observes is damage, never a missing body and never a skip:
    /// a prune pass deletes rows atomically and never leaves corrupt frames
    /// behind.
    #[error("body frame of block {hash} at height {height} is corrupt: {evidence}")]
    BodyCorrupt {
        /// Block height.
        height: u32,
        /// Block hash the chain names.
        hash: Hash256,
        /// The frame evidence.
        evidence: &'static str,
    },
    /// The stored body is not the block the tree names.
    #[error("body of block {hash} at height {height} does not decode: {source}")]
    BodyDecode {
        /// Block height.
        height: u32,
        /// Block hash the chain names.
        hash: Hash256,
        /// Why the body was refused.
        #[source]
        source: BodyDecodeError,
    },
    /// The block's header does not meet its proof-of-work target.
    #[error("block {hash} at height {height} fails its proof-of-work check: {source}")]
    ProofOfWork {
        /// Block height.
        height: u32,
        /// Block hash the chain names.
        hash: Hash256,
        /// The header check that failed.
        #[source]
        source: Box<ChainError>,
    },
    /// The body breaks its header commitments or the context-free body rules.
    #[error("body of block {hash} at height {height} does not match its header: {source}")]
    Binding {
        /// Block height.
        height: u32,
        /// Block hash the chain names.
        hash: Hash256,
        /// The commitment that failed.
        #[source]
        source: ConsensusError,
    },
    /// The block has no stored undo record.
    #[error("block {hash} at height {height} has no stored undo record")]
    UndoMissing {
        /// Block height.
        height: u32,
        /// Block hash the chain names.
        hash: Hash256,
    },
    /// The undo store failed to read the record.
    #[error("reading the undo record of block {hash} at height {height} failed: {source}")]
    UndoRead {
        /// Block height.
        height: u32,
        /// Block hash the chain names.
        hash: Hash256,
        /// The storage failure.
        #[source]
        source: BoundedReadError,
    },
    /// The chainstate closed for recovery: verification refuses to declare
    /// anything verified from a chain that can no longer admit mutations.
    /// This names no block; it is fail-closed admission state, not damage.
    #[error("chainstate is closed for recovery")]
    ClosedForRecovery,
    /// The requesting caller cancelled verification. This names no block;
    /// it is an operator stop, not damage and not unavailable history.
    #[error("block verification was interrupted")]
    Interrupted,
    /// The stored undo record does not decode against its block.
    #[error("undo record of block {hash} at height {height} does not decode: {source}")]
    UndoDecode {
        /// Block height.
        height: u32,
        /// Block hash the chain names.
        hash: Hash256,
        /// The decode failure.
        #[source]
        source: Box<UndoCodecError>,
    },
}

/// Verifies the newest applied blocks, checking each back to the window's
/// first height.
///
/// PRE: none. The read needs no chain-transition exclusion: an applied
/// ancestor's body and undo record are immutable, and pruning is held off by
/// the history lease taken here.
///
/// POST: `Passed` means every block in the window satisfied `request.level`
/// while the request latch stayed quiet, admission stayed open, and the
/// history pin stayed live through completion. A block above the data floor
/// that is missing or damaged is an error, even when the window also reaches
/// data below the floor. A floor is the prune line the retention owner
/// reports, or one past the snapshot base for an assumed-valid chainstate.
/// A cancelled request is [`VerifyError::Interrupted`]; a chainstate closed
/// for recovery is [`VerifyError::ClosedForRecovery`]; a withdrawn pin is
/// `SkippedNoBlockData`, even when the rows are still readable.
///
/// INVARIANT: no history is read unpinned, and a read that finds nothing
/// after the owner withdrew the pin is `SkippedNoBlockData`, never damage.
/// The pin is also checked at every progress boundary and before reporting
/// success, so a withdrawal the walk already passed still refuses `Passed`.
/// None of these checks holds a transition or registry lock across disk IO:
/// each is one atomic or registry read beside the IO, never around it.
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

/// Pins history from the lowest height the window can use, or reports the
/// height at which the window is wholly unavailable.
///
/// The retention owner answers a request below its executed prune line, or
/// below an in-flight prune claim, with that line (`Pruned` then `Reserved`).
/// The window is raised to the owner's line and requested again, so the
/// blocks the node still holds are verified and the rest is reported as
/// skipped. A refusal that names no higher line, a refusal after the line
/// moved twice, and shutdown all leave nothing pinned.
fn pin_window(
    chainstate: &Chainstate,
    requested: u32,
    tip_height: u32,
) -> Result<(HistoryLease, u32), u32> {
    // The snapshot base block itself was never validated here, so the first
    // block this chainstate connected is the one above it.
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

/// One initial request, one raise to the executed prune line, one raise to an
/// in-flight claim above it.
const PIN_ATTEMPTS: usize = 3;

/// Why a walk ended before it finished the window.
enum Stop {
    /// The window's data became unavailable at `height`.
    Skipped { height: u32 },
    /// The requesting caller cancelled verification.
    Interrupted,
    /// Damage inside the window.
    Failed(VerifyError),
}

impl From<VerifyError> for Stop {
    fn from(error: VerifyError) -> Self {
        Self::Failed(error)
    }
}

/// What the block tree says about one ancestor, copied out so no tree guard
/// is held across storage reads.
struct Ancestor {
    hash: Hash256,
    parent: NodeId,
    prev_hash: Hash256,
    segwit_active: bool,
}

struct Walk<'a> {
    chainstate: &'a Chainstate,
    store: Arc<dyn BlockBodyStore>,
    /// Held until the walk is dropped.
    lease: HistoryLease,
    level: CheckLevel,
    cancellation: Option<LatchReader>,
}

impl Walk<'_> {
    /// Checks heights `tip_height` down to `start` and returns how many.
    /// Cancellation, recovery closure, and pin liveness are polled at every
    /// progress boundary and once more before reporting success, beside the
    /// storage reads rather than around them.
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
        // A withdrawal past the last boundary still refuses success; the pin
        // covered the whole window, so the tip is the highest height it no
        // longer protects.
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

    /// Reads one ancestor from the tree. A node the tree no longer holds,
    /// or holds at another height or hash, is a missing block.
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
        // Parent-derived activation, computed only for the startup-strength
        // level: the RPC levels never consult it.
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
        // The bounded verification read preserves corrupt referenced frames
        // instead of mapping them to `None`: corruption surfaces as damage
        // even without a history floor, where a missing body would skip.
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

    /// Classifies a read that found nothing. While the pin is live the owner
    /// guarantees the row stays, so the absence is damage. Once the owner
    /// withdrew the pin, a prune pass may have taken the row and the absence
    /// proves nothing. A failed read is always damage; a prune pass deletes
    /// rows atomically and never turns them into read errors.
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
    // Witness commitments, full witness weight, finality, and UTXO/script
    // execution are contextual and stay out, so a body that only mutates
    // witness data still passes this level, as Core's level one does.
    verify_block_non_contextual(block).map_err(|source| VerifyError::Binding {
        height,
        hash,
        source,
    })
}

/// Checks header-body binding, including the witness commitment, for the
/// startup-strength level only. The Merkle half repeats the body rules
/// above through the consensus-owned check; no witness logic lives here.
fn check_binding(block: &Block, height: u32, ancestor: &Ancestor) -> Result<(), VerifyError> {
    let hash = ancestor.hash;
    check_block_body_binding(block, ancestor.segwit_active).map_err(|source| VerifyError::Binding {
        height,
        hash,
        source,
    })
}

#[cfg(test)]
#[path = "../tests/unit/verify_tests.rs"]
mod tests;
