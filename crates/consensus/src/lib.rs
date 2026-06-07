//! Consensus validation surfaces for bitcoin-rs.
//!
//! The `kernel` feature enables a bitcoinkernel-backed authority path. With the
//! feature off, the crate builds a portable Rust validation path that delegates
//! script execution to `bitcoin-rs-script` and keeps consensus-facing rule checks
//! in small, testable modules.

#![forbid(unsafe_op_in_unsafe_fn)]

/// BIP112 sequence-lock checks.
pub mod bip112;
/// BIP113 median-time-past checks.
pub mod bip113;
/// BIP141 segwit checks.
pub mod bip141;
/// BIP143 segwit-v0 sighash checks.
pub mod bip143;
/// BIP30 duplicate-transaction checks.
pub mod bip30;
/// BIP34 coinbase height checks.
pub mod bip34;
/// BIP341 taproot checks.
pub mod bip341;
/// BIP342 tapscript checks.
pub mod bip342;
/// BIP65 locktime checks.
pub mod bip65;
/// BIP66 DER-signature checks.
pub mod bip66;
/// BIP68 relative-locktime checks.
pub mod bip68;
/// BIP9 versionbits checks.
pub mod bip9;
/// Dual-path block connection.
pub mod connect_block;
/// Feature-gated bitcoinkernel wrapper.
pub mod kernel;
/// Portable Rust validator.
pub mod rust_path;
/// Block rule checks.
pub mod verify_block;
/// Transaction rule checks.
pub mod verify_tx;

pub use bip9::{DeploymentContext, DeploymentParams, DeploymentState, compute_state};
pub use connect_block::connect_block_dual_path;
pub use rust_path::{BlockState, RustValidator, TipState, UtxoView};
pub use verify_block::{
    BlockRuleContext, verify_block_rules, verify_block_rules_borrowed,
    verify_block_rules_borrowed_contextual, verify_block_rules_borrowed_contextual_with_txids,
    verify_block_rules_borrowed_contextual_with_txids_and_witness_hint,
    verify_block_rules_contextual,
};
pub use verify_tx::{
    is_final_tx, verify_coinbase_script_sig_size, verify_transaction, verify_transaction_borrowed,
    verify_transaction_borrowed_with_mtp, verify_transaction_with_mtp,
};

use thiserror::Error;

/// Consensus validation error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// A transaction has no inputs.
    #[error("transaction has no inputs")]
    EmptyInputs,
    /// A transaction has no outputs.
    #[error("transaction has no outputs")]
    EmptyOutputs,
    /// Coinbase scriptSig length is outside the consensus-allowed 2..=100 byte range.
    #[error("coinbase scriptSig length {len} outside allowed range 2..=100 bytes")]
    CoinbaseScriptSigSize {
        /// Observed coinbase scriptSig length in bytes.
        len: usize,
    },
    /// A non-coinbase transaction contains a null previous output.
    #[error("non-coinbase transaction input {input_index} spends a null outpoint")]
    NullPrevout {
        /// Input index containing the null outpoint.
        input_index: usize,
    },
    /// A transaction spends the same previous output more than once.
    #[error("transaction contains duplicate input {input_index}")]
    DuplicateInput {
        /// Input index that repeats an earlier outpoint.
        input_index: usize,
    },
    /// A required UTXO was not present in the supplied view.
    #[error("missing prevout for input {input_index}")]
    MissingPrevout {
        /// Input index whose previous output is unavailable.
        input_index: usize,
    },
    /// Total output value exceeds Bitcoin's maximum money supply.
    #[error("transaction output value exceeds max money")]
    OutputValueOverflow,
    /// Total input value is smaller than total output value.
    #[error("transaction spends {input_value} sats but creates {output_value} sats")]
    InputsLessThanOutputs {
        /// Total input value in satoshis.
        input_value: u64,
        /// Total output value in satoshis.
        output_value: u64,
    },
    /// Script verification failed.
    #[error("script verification failed at input {input_index}: {reason}")]
    Script {
        /// Input index that failed script verification.
        input_index: usize,
        /// Script failure reason.
        reason: String,
    },
    /// Sigop cost exceeds consensus maximum.
    #[error("sigop cost {cost} exceeds max {max}")]
    SigopsLimit {
        /// Observed sigop cost.
        cost: u32,
        /// Consensus maximum.
        max: u32,
    },
    /// Block has no transactions.
    #[error("block has no transactions")]
    EmptyBlock,
    /// First transaction is not coinbase.
    #[error("block first transaction is not coinbase")]
    MissingCoinbase,
    /// A non-first transaction is coinbase.
    #[error("block transaction {tx_index} is coinbase outside position 0")]
    ExtraCoinbase {
        /// Transaction index.
        tx_index: usize,
    },
    /// Block merkle tree has a duplicate subtree mutation.
    #[error("block merkle tree contains a duplicate transaction mutation")]
    MerkleMutation,
    /// Block merkle root does not match transaction ids.
    #[error("block merkle root mismatch")]
    MerkleRoot,
    /// Block witness commitment does not match.
    #[error("block witness commitment mismatch")]
    WitnessCommitment,
    /// Block weight exceeds consensus maximum.
    #[error("block weight {weight} exceeds max {max}")]
    BlockWeight {
        /// Observed block weight.
        weight: u64,
        /// Consensus maximum block weight.
        max: u64,
    },
    /// BIP rule check failed.
    #[error("{bip}: {reason}")]
    Bip {
        /// BIP identifier.
        bip: &'static str,
        /// Failure reason.
        reason: String,
    },
    /// Kernel path failed or is not configured for the requested operation.
    #[error("kernel validation failed: {0}")]
    Kernel(String),
    /// Consensus encoding or decoding failed.
    #[error("consensus encoding failed: {0}")]
    Encoding(String),
}

/// Maximum valid money supply in satoshis.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Maximum block sigop cost after segwit scaling.
pub const MAX_BLOCK_SIGOPS_COST: u32 = 80_000;
