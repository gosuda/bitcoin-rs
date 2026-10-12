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
    #[error("block-tree node index {index} does not fit in NodeId")]
    NodeIdOverflow { index: usize },
    #[error("unknown block-tree node {id:?}")]
    UnknownNode { id: NodeId },
    #[error("duplicate block header {hash}")]
    DuplicateHeader { hash: Hash256 },
    #[error("header {hash} is known invalid")]
    KnownInvalidHeader { hash: Hash256 },
    #[error("missing parent header {prev_hash}")]
    MissingParent { prev_hash: Hash256 },
    #[error("header extends invalid parent {parent:?}")]
    InvalidParent { parent: NodeId },
    #[error("header version {version:#010x} is below required {required} at height {height}")]
    BadVersion {
        version: i32,
        required: i32,
        height: u32,
    },
    #[error(
        "header timestamp {timestamp} at height {height} is below the timewarp floor {minimum}"
    )]
    TimewarpAttack {
        height: u32,
        timestamp: u32,
        minimum: u32,
    },

    #[error("header prev hash {actual_prev} does not match expected parent {expected_prev}")]
    NonContinuousHeader {
        expected_prev: Hash256,
        actual_prev: Hash256,
    },
    #[error("header {hash} has zero proof-of-work target")]
    ZeroTarget { hash: Hash256 },
    #[error("header {hash} target {target} exceeds network limit {max_target}")]
    TargetExceedsLimit {
        hash: Hash256,
        target: ChainWork,
        max_target: ChainWork,
    },
    #[error("header {hash} does not satisfy proof of work target {target}")]
    InvalidPow { hash: Hash256, target: ChainWork },
    #[error("nBits {actual:08x} does not match expected {expected:08x} at height {height}")]
    NbitsMismatch {
        actual: u32,
        expected: u32,
        height: u32,
    },
    #[error("chainwork overflow at header {hash}")]
    ChainworkOverflow { hash: Hash256 },
    #[error("height overflow after parent {parent:?}")]
    HeightOverflow { parent: NodeId },
    #[error("no common ancestor while planning reorg from {old_tip:?} to {new_tip:?}")]
    NoCommonAncestor { old_tip: NodeId, new_tip: NodeId },
    #[error("header {hash} timestamp {timestamp} is not greater than median-time-past {median}")]
    TimestampTooEarly {
        hash: Hash256,
        timestamp: u32,
        median: u32,
    },
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
