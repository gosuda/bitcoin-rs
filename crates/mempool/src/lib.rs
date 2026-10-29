#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod accounting;
mod admission;
mod chunk_index;
mod entry;
pub mod eviction;
mod fee_diagram;
mod fee_estimator;
pub mod fee_history;
mod gateway;
mod mutation;
mod orphan;
mod package;
mod policy;
mod pool;
mod rbf;
mod reader;
mod rolling_min_fee;
pub mod snapshot;
pub mod standardness;
mod submit_package;
mod truc;

pub use admission::{
    AdmissionChain, ChainAdmissionSnapshot, OrphanRetry, PrevoutMeta, SubmitError, SubmitOutcome,
};
pub use chunk_index::{ChunkView, ProjectedChunks};
pub use entry::{EntryId, MempoolEntry};
pub(crate) use eviction::evict_lowest_fee_packages;
pub use fee_diagram::FeeDiagramError;
pub use fee_estimator::{FeeEstimator, FeeRate};
pub use gateway::{
    AdmissionRequest, AdmitError, AdmitOutcome, BodyInterest, ChainChangeError, ChainChangeGuard,
    CompositeObserver, MempoolGateway, MempoolObserver,
};
#[cfg(any(test, feature = "test-seam"))]
pub use gateway::{arm_admission_park, reset_admission_park};
pub use mutation::{
    AdmissionOrigin, LocalOrigin, MutationChange, MutationEnvelope, MutationOutcome,
    MutationResult, PeerToken, RemovalReason,
};
pub use policy::{MempoolLimits, MempoolPolicySnapshot, PolicyError};
pub use pool::{
    BlockRemovalPlan, Mempool, MempoolError, MempoolMiningSnapshot, MempoolStats, OutpointSpender,
    PrioritiseError, PrioritisedTransaction, ScriptHash, SnapshotEntry, package_heap_usage,
};
pub use rbf::{RbfError, required_fee};
#[cfg(any(test, feature = "test-seam"))]
pub use rbf::{ReplacementCandidate, ReplacementPlan};
pub use reader::MempoolReader;
pub use standardness::{StandardnessError, StandardnessPolicy, is_standard_tx};
pub use submit_package::{PackageSubmission, PackageTxResult};
pub use truc::TrucError;
