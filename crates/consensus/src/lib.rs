//! Consensus validation surfaces for bitcoin-rs.
//!
//! Script verification has two backends. The native Rust interpreter in
//! `bitcoin-rs-script` executes every consensus spend class: legacy, P2SH,
//! `SegWit` v0, and Taproot key-path and script-path. The `kernel` feature
//! routes the same checks through bitcoinkernel (Bitcoin Core's C++ engine)
//! and is the production default in this crate and in `bitcoin-rs-node`.
//! The `bin/bitcoin-rs` binary defaults to `["fjall", "redb", "zmq"]` (no
//! `kernel`), so `cargo build -p bitcoin-rs` uses the native interpreter.
//! Issue #213 keeps `kernel` as the library default until native wins the
//! signed-spend and full-replay gates; see
//! `docs/contracts/validation-default.md`.

#![forbid(unsafe_op_in_unsafe_fn)]

/// Maximum consensus script size in bytes.
pub const MAX_SCRIPT_SIZE: usize = 10_000;

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
/// Parse-once block state shared by the native apply path.
pub mod block_view;
/// Feature-gated bitcoinkernel wrapper.
pub mod kernel;
/// Portable Rust validator.
pub mod rust_path;
/// Consensus transaction sigop-cost accounting.
pub mod sigops;
/// Private AVX2 SHA256d64 kernel for Merkle hashing.
mod sha256d64;
/// Block rule checks.
pub mod verify_block;
/// Transaction rule checks.
pub mod verify_tx;

pub use bip9::{
    BIP9_PERIOD, CSV_DEPLOYMENT_ID, DeploymentContext, DeploymentParams, DeploymentState,
    SEGWIT_DEPLOYMENT_ID, SoftforkState, compute_state, deployment_params,
};
pub use bip113::{MEDIAN_TIME_PAST_WINDOW, locktime_cutoff};
pub use block_view::BlockView;
pub use rust_path::{TipState, UtxoView};
pub use sigops::transaction_sigop_cost;
pub use verify_block::{
    BlockRuleContext, verify_block_rules, verify_block_rules_precomputed,
    verify_merkle_root_with_txids,
};
pub use verify_tx::{
    ScriptStageTimings, is_final_tx, verify_block_input_scripts, verify_coinbase_script_sig_size,
    verify_transaction, verify_transaction_non_script,
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
    #[error("block contains multiple coinbase transactions")]
    MultipleCoinbase,
    /// Transaction merkle root does not match the block header.
    #[error("block merkle root mismatch")]
    MerkleRootMismatch,
    /// Block weight exceeds the BIP141 maximum.
    #[error("block weight {weight} exceeds max {max}")]
    BlockWeightExceeded {
        /// Observed block weight.
        weight: u64,
        /// Consensus maximum block weight.
        max: u64,
    },
    /// Block transaction vector and resolved-prevout matrix lengths differ.
    #[error("resolved prevout matrix has {actual} rows for {expected} transactions")]
    PrevoutMatrixSize {
        /// Number of transactions in the block.
        expected: usize,
        /// Number of resolved-prevout rows supplied.
        actual: usize,
    },
    /// Block subsidy/fee total or another money-valued consensus arithmetic overflowed.
    #[error("consensus money arithmetic overflow")]
    MoneyOverflow,
    /// A BIP-specific rule failed.
    #[error("{bip}: {reason}")]
    Bip {
        /// Short BIP identifier.
        bip: &'static str,
        /// Human-readable rule failure.
        reason: String,
    },
    /// Kernel-backed verification failed outside an input-script verdict.
    #[error("kernel verification failed: {0}")]
    Kernel(String),
}

/// Consensus maximum money in satoshis (21 million BTC).
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
/// BIP141 block weight limit.
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
/// Consensus transaction/block sigop-cost limit.
pub const MAX_BLOCK_SIGOPS_COST: u32 = 80_000;
