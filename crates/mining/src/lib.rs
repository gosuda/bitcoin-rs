#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// BIP22 reject-reason vocabulary.
mod bip22;
/// Coinbase transaction assembly.
mod coinbase;
/// Candidate chain context.
mod context;
/// Node-facing mining control contract.
pub mod control;
/// Node-backed candidate lifecycle service.
mod coordinator;
/// Authoritative-mutation wake seam for long-poll mining.
mod generation_signal;
/// Network hash-rate estimation.
mod network_hashps;
/// Transaction selection policy.
pub mod policy;
/// Transport-neutral candidate assembly.
mod template;

pub use bip22::{chain_reject_reason, consensus_reject_reason, header_reject_reason};
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
pub use coordinator::snapshot_for_selection;
pub use coordinator::{
    AppliedTipSource, ChainContextSource, MempoolSequenceWake, MempoolSnapshotSource, MiningService,
};
pub use generation_signal::MiningGenerationSignal;
#[cfg(any(test, feature = "test-seam"))]
pub use control::FakeMiningControl;
pub use network_hashps::{estimate_network_hashps, network_hash_ps};
pub use template::{
    Candidate, CandidateContext, CandidateTransaction, TemplateId, assemble_candidate,
    assemble_ordered_candidate, solve_block,
};
