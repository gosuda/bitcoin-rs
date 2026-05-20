#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// BIP9 deployment-state memoization cache.
pub mod bip9_cache;
/// Header acceptance and proof-of-work validation.
pub mod header_sync;
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

pub use bip9_cache::{Bip9Cache, CachedState};
pub use bitcoin_rs_primitives::Network;
pub use header_sync::accept_headers;
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
}
