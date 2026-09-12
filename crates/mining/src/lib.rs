#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Coinbase transaction assembly.
pub mod coinbase;
/// Candidate chain context.
pub mod context;
/// Node-facing mining control contract.
pub mod control;
/// Node-backed candidate lifecycle service.
pub mod coordinator;
/// Transaction selection policy.
pub mod policy;
/// Transport-neutral candidate assembly.
pub mod template;

pub use coinbase::{
    MiningError, WITNESS_RESERVED_VALUE, update_uncommitted_block_structures,
    witness_commitment_script,
};
pub use context::MiningChainContext;
pub use control::{
    AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockTemplateRequest,
    BlockTemplateResult, BlockValidationResult, GenerateRequest, GenerateSelection, GenerateTx,
    GeneratedBlock, LastCandidateInfo, MiningCapability, MiningControl, MiningControlError,
    MiningInfo, MiningRule, SignetMiningInfo, TemplateMutation, difficulty_for_bits,
};
pub use coordinator::DEFAULT_MEMPOOL_UPDATE_WAIT;
pub use coordinator::snapshot_for_selection;
pub use coordinator::{
    AppliedTipSource, ChainContextSource, GenerationKey, MempoolSequenceWake,
    MempoolSnapshotSource, MiningService,
};
pub use template::{
    Candidate, CandidateContext, CandidateTransaction, TemplateId, assemble_candidate,
    assemble_ordered_candidate, solve_block,
};
