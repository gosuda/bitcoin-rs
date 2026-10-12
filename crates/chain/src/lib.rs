#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// BIP9 deployment-state memoization cache.
mod bip9_cache;
/// Neutral block-body read seam.
mod block_body;
/// Cumulative chain transaction count arithmetic.
mod count;
/// BIP9/softfork lookups over [`BlockTree`].
mod deployment;
/// Header acceptance and proof-of-work validation.
pub mod header_sync;
/// Initial block download state of the applied chain.
mod ibd;
/// Block-tree node types.
pub mod node;
/// Synchronization progress of the applied chain.
mod progress;
/// Regtest block and proof-of-work builders shared by cross-crate test
/// harnesses. Compiled only under the `test-seam` feature.
#[cfg(feature = "test-seam")]
pub mod regtest_fixture;
/// Reorganization planning.
mod reorg;
/// Best-tip snapshot type.
mod tip;
/// Read-only active-tip notification contract.
mod tip_wait;
/// One transition domain split into mutation and stable-read roles.
mod transition;
/// In-memory block tree.
mod tree;
/// Read-only capabilities over chain publications and topology.
mod view;

use bitcoin_rs_primitives::Hash256;
use thiserror::Error;

pub use bitcoin_rs_consensus::SoftforkState;
pub use block_body::BlockBodySource;
pub use count::ChainTxCount;
pub use deployment::{
    DeploymentQueryError, DeploymentStatus, SignallingDeployment, VersionBitsStatus,
    bip30_duplicate_scan_required, candidate_version, deployment_statuses, signalling_deployments,
    softfork_state,
};
pub use header_sync::{
    HeaderAdmission, HeaderValidationMode, accept_headers, block_work, compact_is_met_by,
    current_unix_seconds, permitted_difficulty_transition, validate_contextual_header,
    validate_pow,
};
pub use ibd::InitialBlockDownload;
pub use node::{BlockHeader, BlockTreeNode, ChainWork, NodeId, NodeStatus};
pub use progress::{ChainProgress, ChainProgressReader};
pub use reorg::{ReorgPlan, plan_reorg};
pub use tip::TipSnapshot;
pub use tip_wait::{ActiveTipWait, TipWaitCondition};
pub use transition::{
    StableRead, StableReadGuard, TransitionAuthority, TransitionAuthorityGuard, TransitionDomain,
};
pub use tree::BlockTree;
pub use view::{BlockTreeReader, LatchReader, TipReader};

/// A caller-owned bound on fallback ancestor parent hops was exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("block ancestry read budget exhausted")]
pub struct AncestryBudgetExceeded;

/// Errors returned by header sync, block-tree, and reorg planning operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    /// A slab index could not fit into the compact `NodeId` representation.
    #[error("block-tree node index {index} does not fit in NodeId")]
    NodeIdOverflow {
        index: usize,
    },
    /// A caller referenced an unknown node id.
    #[error("unknown block-tree node {id:?}")]
    UnknownNode {
        id: NodeId,
    },
    /// The header is already present in the tree.
    #[error("duplicate block header {hash}")]
    DuplicateHeader {
        hash: Hash256,
    },
    /// A previously admitted header is known to be invalid.
    #[error("header {hash} is known invalid")]
    KnownInvalidHeader {
        hash: Hash256,
    },
    /// A non-root header refers to a parent hash not present in the tree.
    #[error("missing parent header {prev_hash}")]
    MissingParent {
        prev_hash: Hash256,
    },
    /// The candidate extends a header that this node has marked invalid.
    #[error("header extends invalid parent {parent:?}")]
    InvalidParent {
        parent: NodeId,
    },
    /// The header version is below the floor a buried deployment requires.
    #[error("header version {version:#010x} is below required {required} at height {height}")]
    BadVersion {
        version: i32,
        required: i32,
        height: u32,
    },
    /// A BIP94 retarget-boundary timestamp lies more than `MAX_TIMEWARP`
    /// seconds below its parent's timestamp.
    #[error(
        "header timestamp {timestamp} at height {height} is below the timewarp floor {minimum}"
    )]
    TimewarpAttack {
        height: u32,
        timestamp: u32,
        minimum: u32,
    },

    /// A supplied parent does not match the header's previous-block hash.
    #[error("header prev hash {actual_prev} does not match expected parent {expected_prev}")]
    NonContinuousHeader {
        expected_prev: Hash256,
        actual_prev: Hash256,
    },
    /// A header's compact target is zero.
    #[error("header {hash} has zero proof-of-work target")]
    ZeroTarget {
        hash: Hash256,
    },
    /// A header's compact target exceeds the network proof-of-work limit.
    #[error("header {hash} target {target} exceeds network limit {max_target}")]
    TargetExceedsLimit {
        hash: Hash256,
        target: ChainWork,
        max_target: ChainWork,
    },
    /// A header hash does not satisfy its compact target.
    #[error("header {hash} does not satisfy proof of work target {target}")]
    InvalidPow {
        hash: Hash256,
        target: ChainWork,
    },
    /// A header's compact target does not match the network difficulty expected at its height.
    #[error("nBits {actual:08x} does not match expected {expected:08x} at height {height}")]
    NbitsMismatch {
        actual: u32,
        expected: u32,
        height: u32,
    },
    /// Adding block work to parent chainwork overflowed 256 bits.
    #[error("chainwork overflow at header {hash}")]
    ChainworkOverflow {
        hash: Hash256,
    },
    /// A child height would overflow `u32`.
    #[error("height overflow after parent {parent:?}")]
    HeightOverflow {
        parent: NodeId,
    },
    /// Reorg planning walked to a root without reaching a common ancestor.
    #[error("no common ancestor while planning reorg from {old_tip:?} to {new_tip:?}")]
    NoCommonAncestor {
        old_tip: NodeId,
        new_tip: NodeId,
    },
    /// A header's timestamp is not strictly greater than the median-time-past
    /// of its previous 11 blocks.
    #[error("header {hash} timestamp {timestamp} is not greater than median-time-past {median}")]
    TimestampTooEarly {
        hash: Hash256,
        timestamp: u32,
        median: u32,
    },
    /// A header's timestamp is too far ahead of the current network-adjusted time.
    #[error(
        "header {hash} timestamp {timestamp} exceeds maximum allowed future time {max_allowed}"
    )]
    TimestampTooFarAhead {
        hash: Hash256,
        timestamp: u32,
        /// Maximum allowed future timestamp in Unix seconds (`now + 7200`).
        max_allowed: u32,
    },
}
