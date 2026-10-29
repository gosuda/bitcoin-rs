#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

mod block_body;
mod count;
mod deployment;
pub mod header_sync;
mod ibd;
pub mod node;
mod progress;
#[cfg(feature = "test-seam")]
pub mod regtest_fixture;
mod reorg;
mod tip_wait;
mod transition;
mod tree;
mod view;

use bitcoin_rs_primitives::Hash256;
use thiserror::Error;

pub use bitcoin_rs_consensus::SoftforkState;
pub use block_body::{BlockBodyReadError, BlockBodySource};
pub use count::ChainTxCount;
pub use deployment::{
    DeploymentQueryError, DeploymentStatus, SignallingDeployment, VersionBitsStatus,
    bip30_duplicate_scan_required, candidate_version, deployment_statuses, signalling_deployments,
    softfork_state,
};
pub use header_sync::{
    AcceptHeaders, HeaderAdmission, HeaderValidationMode, accept_headers, block_work,
    compact_is_met_by, compact_to_target, current_unix_seconds, permitted_difficulty_transition,
    validate_contextual_header, validate_pow,
};
pub use ibd::InitialBlockDownload;
pub use node::{BlockHeader, BlockTreeNode, ChainWork, NodeId, NodeStatus};
pub use progress::{ChainProgress, ChainProgressReader};
pub use reorg::{ReorgPlan, plan_reorg};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipSnapshot {
    pub tip_id: NodeId,
    pub height: u32,
    pub chainwork: ChainWork,
    pub hash: Hash256,
    pub chain_tx_count: ChainTxCount,
}

pub use tip_wait::{ActiveTipWait, TipWaitCondition};
pub use transition::{
    StableRead, StableReadGuard, TransitionAuthority, TransitionAuthorityGuard, TransitionDomain,
};
pub use tree::{BlockTree, InvalidationOutcome};
pub use view::{BlockTreeReader, LatchReader, TipReader};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("block ancestry read budget exhausted")]
pub struct AncestryBudgetExceeded;

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
        max_allowed: u32,
    },
}
