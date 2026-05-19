#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Mempool entry metadata.
pub mod entry;
/// Package eviction policy.
pub mod eviction;
/// Pareto-front transaction priority ordering.
pub mod pareto;
/// Mempool policy limits.
pub mod policy;
/// Mempool indexes and mutation API.
pub mod pool;
/// BIP125 replacement-by-fee checks.
pub mod rbf;

pub use entry::{EntryId, MempoolEntry};
pub use eviction::evict_lowest_fee_packages;
pub use pareto::ParetoFront;
pub use policy::{MempoolLimits, PolicyError};
pub use pool::{Mempool, MempoolError, ScriptHash};
pub use rbf::{RbfError, ReplacementCandidate, ReplacementPlan};
