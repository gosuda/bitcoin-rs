#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, verification))]
pub(crate) mod projection_model;
#[cfg(test)]
pub(crate) mod test_error;

mod bip22;
mod coinbase;
mod context;
mod control;
mod coordinator;
mod generation_signal;
mod network_hashps;
mod policy;
mod template;

pub use bip22::{
    STALE_PARENT_REASON, chain_reject_reason, consensus_reject_reason, header_reject_reason,
};
pub use coinbase::{
    MiningError, WITNESS_RESERVED_VALUE, needs_witness_reserved_value,
    update_uncommitted_block_structures, witness_commitment_script,
};
pub use context::MiningChainContext;
#[cfg(any(test, feature = "test-seam"))]
pub use control::FakeMiningControl;
pub use control::{
    AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockTemplateRequest,
    BlockTemplateResult, BlockValidationResult, GenerateRequest, GenerateSelection, GenerateTx,
    GeneratedBlock, LastCandidateInfo, MiningCapability, MiningControl, MiningControlError,
    MiningInfo, MiningRule, SignetMiningInfo, TemplateMutation, difficulty_for_bits,
};
pub use coordinator::snapshot_for_selection;
pub use coordinator::{
    AppliedTipSource, ChainContextSource, MempoolSequenceWake, MempoolSnapshotSource,
    MiningService, PreparedTemplateBody,
};
pub use generation_signal::MiningGenerationSignal;
pub use network_hashps::{estimate_network_hashps, network_hash_ps};
pub use template::{
    Candidate, CandidateContext, CandidateTransaction, CoinbaseBudget, SelectedBody, SelectedTx,
    TemplateId, assemble_candidate, assemble_ordered_candidate, select_template_body,
    select_template_body_after, solve_block,
};

#[cfg(feature = "pool")]
pub mod pool;
