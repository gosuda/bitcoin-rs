#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Coinbase transaction assembly.
pub mod coinbase;
/// Transaction selection policy.
pub mod policy;
/// BIP22/23 block template serialization.
pub mod template;

pub use coinbase::{
    CoinbaseTemplateConfig, MiningError, block_subsidy, build_coinbase_template,
    witness_commitment_script,
};
pub use policy::MiningPolicy;
pub use template::{BlockTemplate, BlockTemplateParams, TemplateTransaction};
