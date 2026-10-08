#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Mempool outputs layered over confirmed coin lookup.
mod accept;
/// Shared resolved-input accounting.
mod accounting;
/// Shared transaction preparation, retries, and gateway lifecycle queries.
mod admission;
/// Mempool entry metadata.
mod entry;
/// Package eviction policy.
pub mod eviction;
/// Checked fee diagrams over immutable projections of the admitted graph.
mod fee_diagram;
/// Fee-rate history-based fee-rate estimator.
mod fee_estimator;
/// Fee-estimator history datadir persistence.
pub mod fee_history;
/// Single mutation gateway and observer seam in front of the pool.
mod gateway;
/// Mutation records returned by every mutating pool method.
mod mutation;
/// Orphan transaction pool for transactions with missing parents.
mod orphan;
/// Package shape and ephemeral-spend policy.
mod package;
/// Pareto-front transaction priority ordering.
mod pareto;
/// Mempool policy limits.
mod policy;
/// Mempool indexes and mutation API.
mod pool;
/// Core 31.1 replacement fee and graph policy.
mod rbf;
/// Cloneable read-only capability over the mempool.
mod reader;
/// Transaction relay standardness policy.
pub mod standardness;
/// BIP431 topology policy.
mod truc;

pub use admission::{
    AdmissionChain, ChainAdmissionSnapshot, OrphanRetry, PrevoutMeta, SubmitError, SubmitOutcome,
};
pub use entry::{EntryId, MempoolEntry};
pub(crate) use eviction::evict_lowest_fee_packages;
pub use fee_diagram::FeeDiagramError;
pub use fee_estimator::{FeeEstimator, FeeRate};
pub use gateway::{
    AdmissionRequest, AdmitError, AdmitOutcome, ChainChangeError, ChainChangeGuard,
    CompositeObserver, MempoolGateway, MempoolObserver,
};
#[cfg(any(test, feature = "test-seam"))]
pub use gateway::{arm_admission_park, reset_admission_park};
pub use mutation::{
    AdmissionOrigin, LocalOrigin, MutationChange, MutationEnvelope, MutationOutcome,
    MutationResult, PeerToken, RemovalReason,
};
pub(crate) use pareto::ParetoFront;
pub use policy::{MempoolLimits, MempoolPolicySnapshot, PolicyError};
pub use pool::{
    Mempool, MempoolChunk, MempoolError, MempoolMiningSnapshot, MempoolStats, OutpointSpender,
    PrioritiseError, PrioritisedTransaction, ScriptHash, SnapshotEntry,
};
pub use rbf::RbfError;
#[cfg(any(test, feature = "test-seam"))]
pub use rbf::{ReplacementCandidate, ReplacementPlan};
pub use reader::MempoolReader;
pub use standardness::{StandardnessError, StandardnessPolicy, is_standard_tx};
pub use truc::TrucError;
