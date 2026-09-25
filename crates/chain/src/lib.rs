#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// BIP9 deployment-state memoization cache.
mod bip9_cache;
/// Neutral block-body read seam.
mod block_body;
/// BIP9/softfork lookups over [`BlockTree`].
mod deployment;
/// Header acceptance and proof-of-work validation.
pub mod header_sync;
/// Initial block download state of the applied chain.
pub mod ibd;
/// Block-tree node types.
pub mod node;
/// Reorganization planning.
pub mod reorg;
/// Best-tip snapshot type.
pub mod tip;
/// In-memory block tree.
pub mod tree;

use bitcoin_rs_primitives::Hash256;
use thiserror::Error;

pub(crate) use bip9_cache::CachedState;
pub use bitcoin_rs_consensus::SoftforkState;
pub use bitcoin_rs_primitives::Network;
pub use block_body::{BlockBodyMetadata, BlockBodySource};
pub use deployment::{
    SignallingDeployment, bip30_duplicate_scan_required, candidate_version, signalling_deployments,
    softfork_state,
};
pub use header_sync::{
    HeaderAdmission, accept_headers, compact_is_met_by, current_unix_seconds,
    validate_contextual_header, validate_pow,
};
pub use ibd::InitialBlockDownload;
pub use node::{BlockHeader, BlockTreeNode, ChainWork, NodeId, NodeStatus};
pub use reorg::{ReorgPlan, plan_reorg};
pub use tip::TipSnapshot;
pub use tree::BlockTree;

/// Errors returned by header sync, block-tree, and reorg planning operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    /// A slab index could not fit into the compact `NodeId` representation.
    #[error("block-tree node index {index} does not fit in NodeId")]
    NodeIdOverflow {
        /// Slab index that overflowed `u32`.
        index: usize,
    },
    /// A caller referenced an unknown node id.
    #[error("unknown block-tree node {id:?}")]
    UnknownNode {
        /// Missing node id.
        id: NodeId,
    },
    /// The header is already present in the tree.
    #[error("duplicate block header {hash}")]
    DuplicateHeader {
        /// Duplicate header hash.
        hash: Hash256,
    },
    /// A non-root header refers to a parent hash not present in the tree.
    #[error("missing parent header {prev_hash}")]
    MissingParent {
        /// Previous-block hash referenced by the child header.
        prev_hash: Hash256,
    },
    /// The candidate extends a header that this node has marked invalid.
    ///
    /// Core refuses it with `bad-prevblk` before any contextual check runs
    /// (`src/validation.cpp:4228-4231`), so the header never enters the tree.
    #[error("header extends invalid parent {parent:?}")]
    InvalidParent {
        /// Resolved identity of the invalid parent.
        parent: NodeId,
    },
    /// The header version is below the floor a buried deployment requires.
    ///
    /// Core rejects with `bad-version(0x%08x)` once BIP34 (version 2),
    /// BIP66 (version 3), or BIP65 (version 4) is active after the
    /// previous block (`src/validation.cpp:4112-4126`).
    #[error("header version {version:#010x} is below required {required} at height {height}")]
    BadVersion {
        /// The header's signed 32-bit version.
        version: i32,
        /// Minimum version the active deployment requires (2, 3, or 4).
        required: i32,
        /// Candidate header height.
        height: u32,
    },
    /// A BIP94 retarget-boundary timestamp lies more than `MAX_TIMEWARP`
    /// seconds below its parent's timestamp.
    ///
    /// Core rejects with `time-timewarp-attack`
    /// (`src/validation.cpp:4100-4110`).
    #[error(
        "header timestamp {timestamp} at height {height} is below the timewarp floor {minimum}"
    )]
    TimewarpAttack {
        /// Candidate header height (a difficulty-adjustment boundary).
        height: u32,
        /// The header's timestamp.
        timestamp: u32,
        /// Lowest legal timestamp: parent time minus `MAX_TIMEWARP`.
        minimum: u32,
    },
    /// A supplied parent does not match the header's previous-block hash.
    #[error("header prev hash {actual_prev} does not match expected parent {expected_prev}")]
    NonContinuousHeader {
        /// Expected previous-block hash.
        expected_prev: Hash256,
        /// Actual previous-block hash.
        actual_prev: Hash256,
    },
    /// A header's compact target is zero.
    #[error("header {hash} has zero proof-of-work target")]
    ZeroTarget {
        /// Header hash.
        hash: Hash256,
    },
    /// A header's compact target exceeds the network proof-of-work limit.
    #[error("header {hash} target {target} exceeds network limit {max_target}")]
    TargetExceedsLimit {
        /// Header hash.
        hash: Hash256,
        /// Header target decoded from nBits.
        target: ChainWork,
        /// Network proof-of-work limit.
        max_target: ChainWork,
    },
    /// A header hash does not satisfy its compact target.
    #[error("header {hash} does not satisfy proof of work target {target}")]
    InvalidPow {
        /// Header hash.
        hash: Hash256,
        /// Header target decoded from nBits.
        target: ChainWork,
    },
    /// A header's compact target does not match the network difficulty expected at its height.
    #[error("nBits {actual:08x} does not match expected {expected:08x} at height {height}")]
    NbitsMismatch {
        /// Header's declared compact target.
        actual: u32,
        /// Expected compact target from the active parent chain.
        expected: u32,
        /// Candidate header height.
        height: u32,
    },
    /// Adding block work to parent chainwork overflowed 256 bits.
    #[error("chainwork overflow at header {hash}")]
    ChainworkOverflow {
        /// Header hash.
        hash: Hash256,
    },
    /// A child height would overflow `u32`.
    #[error("height overflow after parent {parent:?}")]
    HeightOverflow {
        /// Parent whose child height overflowed.
        parent: NodeId,
    },
    /// Reorg planning walked to a root without reaching a common ancestor.
    #[error("no common ancestor while planning reorg from {old_tip:?} to {new_tip:?}")]
    NoCommonAncestor {
        /// Old tip node id.
        old_tip: NodeId,
        /// New tip node id.
        new_tip: NodeId,
    },
    /// A header's timestamp is not strictly greater than the median-time-past
    /// of its previous 11 blocks.
    #[error("header {hash} timestamp {timestamp} is not greater than median-time-past {median}")]
    TimestampTooEarly {
        /// Header hash.
        hash: Hash256,
        /// Header timestamp (seconds since UNIX epoch).
        timestamp: u32,
        /// Median timestamp of the previous 11 blocks.
        median: u32,
    },
    /// A header's timestamp is too far ahead of the current network-adjusted time.
    #[error(
        "header {hash} timestamp {timestamp} exceeds maximum allowed future time {max_allowed}"
    )]
    TimestampTooFarAhead {
        /// Header hash.
        hash: Hash256,
        /// Header timestamp (seconds since UNIX epoch).
        timestamp: u32,
        /// Maximum allowed timestamp (`now + 7200`).
        max_allowed: u32,
    },
}
