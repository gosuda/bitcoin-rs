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
mod settlement;
#[cfg(any(test, verification, kani))]
pub(crate) mod settlement_model;
pub mod snapshot;
pub mod standardness;
mod submit_package;
#[cfg(test)]
pub(crate) mod test_error {
    #[derive(Debug, thiserror::Error)]
    pub(crate) enum TestError {
        #[error("mempool error: {0}")]
        Mempool(#[from] crate::MempoolError),
        #[error("prioritise error: {0}")]
        Prioritise(#[from] crate::PrioritiseError),
        #[error("rbf error: {0}")]
        Rbf(#[from] crate::RbfError),
        #[error("refusal: {0}")]
        Refusal(#[from] crate::rbf::Refusal),
        #[error("submit error: {0}")]
        Submit(#[from] crate::SubmitError),
        #[error("acceptance reject: {0:?}")]
        AcceptanceReject(#[from] crate::standardness::AcceptanceRejectReason),
        #[error("chain change error: {0}")]
        ChainChange(#[from] crate::ChainChangeError),
        #[error("hash error: {0}")]
        Hash(#[from] bitcoin_rs_consensus::primitives::HashError),
        #[error("try-from-int error: {0}")]
        TryFromInt(#[from] core::num::TryFromIntError),
        #[error("consensus decode error: {0}")]
        Consensus(#[from] bitcoin::consensus::encode::Error),
        #[error("io error: {0}")]
        Io(#[from] std::io::Error),
        #[error("recv timeout error: {0}")]
        RecvTimeout(#[from] std::sync::mpsc::RecvTimeoutError),
        #[error("send error: {0}")]
        Send(#[from] std::sync::mpsc::SendError<()>),
        #[error("infallible")]
        Infallible(#[from] core::convert::Infallible),
        #[error("missing expected value: {0}")]
        Missing(&'static str),
    }

    impl From<&'static str> for TestError {
        fn from(msg: &'static str) -> Self {
            Self::Missing(msg)
        }
    }
}
#[cfg(test)]
pub(crate) mod test_fixtures {
    use bitcoin_rs_consensus::script::{opcode, push_data};

    pub(crate) fn p2sh_true_script() -> Vec<u8> {
        [
            vec![opcode::OP_HASH160, 0x14],
            vec![
                0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7,
                0x7e, 0xba, 0x30, 0xcd, 0x5a, 0x4b,
            ],
            vec![opcode::OP_EQUAL],
        ]
        .concat()
    }

    pub(crate) fn true_redeem_script_sig() -> Vec<u8> {
        push_data(&[opcode::OP_PUSHNUM_1])
    }
}
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
    PrioritiseError, PrioritisedTransaction, ScriptHash, SnapshotEntry, entry_memory_usage,
    package_heap_usage,
};
pub use rbf::{RbfError, required_fee};
#[cfg(any(test, feature = "test-seam"))]
pub use rbf::{ReplacementCandidate, ReplacementPlan};
pub use reader::MempoolReader;
pub use settlement::TransitionFacts;
pub use standardness::{StandardnessError, StandardnessPolicy, is_standard_spend, is_standard_tx};
pub use submit_package::{PackageSubmission, PackageTxResult};
pub use truc::TrucError;
