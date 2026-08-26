#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Coinbase transaction assembly.
pub mod coinbase;
/// Transaction selection policy.
pub mod policy;
/// Transport-neutral candidate assembly.
pub mod template;

pub use coinbase::{MiningError, WITNESS_RESERVED_VALUE, witness_commitment_script};
pub use template::{
    Candidate, CandidateContext, CandidateTransaction, TemplateId, assemble_candidate,
};
