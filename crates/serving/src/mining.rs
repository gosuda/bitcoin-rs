#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, verification))]
pub(crate) mod projection_model;
#[cfg(test)]
pub(crate) mod test_error {
    #[derive(Debug, thiserror::Error)]
    pub(crate) enum TestError {
        #[error(transparent)]
        Chain(#[from] bitcoin_rs_execution::chain::ChainError),
        #[error(transparent)]
        Mining(#[from] crate::mining::MiningError),
        #[error(transparent)]
        MiningControl(#[from] crate::mining::control::MiningControlError),
        #[error(transparent)]
        Mempool(#[from] bitcoin_rs_mempool::MempoolError),
        #[error(transparent)]
        Prioritise(#[from] bitcoin_rs_mempool::PrioritiseError),
        #[cfg(feature = "pool")]
        #[error(transparent)]
        Ledger(#[from] crate::mining::pool::ledger::LedgerError),
        #[error(transparent)]
        BitcoinDecode(#[from] bitcoin::consensus::encode::Error),
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        TryFromInt(#[from] core::num::TryFromIntError),
        #[error(transparent)]
        RecvTimeout(#[from] std::sync::mpsc::RecvTimeoutError),
        #[error("missing expected value: {0}")]
        Missing(&'static str),
    }

    impl From<&'static str> for TestError {
        fn from(msg: &'static str) -> Self {
            Self::Missing(msg)
        }
    }
}

mod bip22;
mod coinbase;
mod context;
mod control;
mod generation_signal;
mod network_hashps;
mod policy;
mod template;

pub use bip22::{
    STALE_PARENT_REASON, chain_reject_reason, consensus_reject_reason, header_reject_reason,
    ordered_assembly_error,
};
pub use coinbase::{
    MiningError, WITNESS_RESERVED_VALUE, image_needs_witness_reserved_value,
    needs_witness_reserved_value, update_uncommitted_block_structures, witness_commitment_script,
};
pub use context::{
    AppliedTipSource, ChainContextSource, MempoolSequenceWake, MempoolSnapshotSource,
    MiningChainContext, PreparedTemplateBody,
};
#[cfg(any(test, feature = "test-seam"))]
pub use control::FakeMiningControl;
pub use control::{
    ASSEMBLY_BUSY, AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockTemplateRequest,
    BlockTemplateResult, BlockValidationResult, GENERATION_RACE, GenerateRequest,
    GenerateSelection, GenerateTx, GeneratedBlock, LastCandidateInfo, MiningCapability,
    MiningControl, MiningControlError, MiningInfo, MiningRule, SignetMiningInfo, TemplateMutation,
    difficulty_for_bits,
};
pub use generation_signal::MiningGenerationSignal;
pub use network_hashps::{estimate_network_hashps, network_hash_ps};
pub use template::{
    Candidate, CandidateContext, CandidateTransaction, CoinbaseBudget, SelectedBody, SelectedTx,
    TemplateId, assemble_candidate, assemble_ordered_candidate, finish_candidate,
    select_template_body, select_template_body_after, solve_block,
};

#[cfg(feature = "pool")]
pub mod pool;
