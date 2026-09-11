#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Coinbase transaction assembly.
pub mod coinbase;
/// Candidate chain context.
pub mod context;
/// Node-facing mining control contract.
pub mod control;
/// Transaction selection policy.
pub mod policy;
/// Transport-neutral candidate assembly.
pub mod template;

pub use coinbase::{MiningError, WITNESS_RESERVED_VALUE, witness_commitment_script};
pub use context::MiningChainContext;
pub use control::{
    AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockTemplateRequest,
    BlockTemplateResult, BlockValidationResult, GenerateRequest, GenerateSelection, GenerateTx,
    GeneratedBlock, LastCandidateInfo, MiningCapability, MiningControl, MiningControlError,
    MiningInfo, MiningRule, SignetMiningInfo, TemplateMutation, difficulty_for_bits,
};
pub use template::{
    Candidate, CandidateContext, CandidateTransaction, TemplateId, assemble_candidate,
    assemble_ordered_candidate, solve_block,
};
