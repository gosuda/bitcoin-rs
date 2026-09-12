#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Coinbase transaction assembly.
pub mod coinbase;
/// Node-backed candidate lifecycle service.
pub mod coordinator;
/// Candidate chain context.
pub mod context;
/// Node-facing mining control contract.
pub mod control;
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
pub use coordinator::{
    CANDIDATE_CACHE_LIMIT, CANDIDATE_GENERATION_RETRIES, DEFAULT_MEMPOOL_UPDATE_WAIT,
    GENERATION_RACE, LONG_POLL_SLICE,
};
pub use coordinator::{
    AppliedTipSource, ChainContextSource, CoordinatorState, GenerationKey, InFlight,
    MempoolSequenceWake, MiningService,
};
pub use coordinator::{
    generation_race, is_generation_race, parse_long_poll_id, signet_info, snapshot_for_selection,
    template_from_candidate,
};
pub use template::{
    Candidate, CandidateContext, CandidateTransaction, TemplateId, assemble_candidate,
    assemble_ordered_candidate, solve_block,
};
