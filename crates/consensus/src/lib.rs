//! Consensus validation surfaces for bitcoin-rs.

#![forbid(unsafe_op_in_unsafe_fn)]

/// Maximum consensus script size in bytes.
pub use bitcoin_rs_script::MAX_SCRIPT_SIZE;
/// Maximum distance a BIP94 candidate timestamp may fall below its parent
/// block's timestamp at a difficulty-adjustment boundary (`MAX_TIMEWARP`, Core
/// `src/consensus/consensus.h:30-37`).
pub const MAX_TIMEWARP: u32 = 600;

/// BIP30 duplicate-transaction checks.
pub mod bip30;
/// BIP34 coinbase height checks.
pub mod bip34;
/// BIP68 relative-locktime checks.
pub mod bip68;
/// BIP9 versionbits checks.
pub mod bip9;
/// Parse-once block state shared by the native apply path.
mod block_view;
/// The one runtime validation-engine selector.
mod engine;
/// Feature-gated bitcoinkernel wrapper.
pub mod kernel;
/// Private AVX2 SHA256d64 kernel for Merkle hashing.
mod sha256d64;
/// Shared transaction-level BIP141 sigop accounting.
mod sigops;
/// Optional Bitcoin Core-compatible USDT tracepoints (`usdt` feature).
pub mod trace;
/// Block rule checks.
pub mod verify_block;
/// Transaction rule checks.
pub mod verify_tx;

pub use bip9::{
    CSV_DEPLOYMENT_ID, DeploymentContext, DeploymentParams, DeploymentState, SEGWIT_DEPLOYMENT_ID,
    SoftforkState, compute_state, deployment_params,
};
/// Number of blocks spanned by median-time-past.
pub const MEDIAN_TIME_PAST_WINDOW: usize = 11;

/// BIP113 locktime-cutoff selection: the one rule every caller shares.
#[must_use]
pub const fn locktime_cutoff(
    csv_active: bool,
    prev_median_time_past: u32,
    candidate_time: u32,
) -> u32 {
    if csv_active {
        prev_median_time_past
    } else {
        candidate_time
    }
}

#[cfg(test)]
mod bip113_tests {
    #[test]
    fn locktime_cutoff_rule_switches_on_csv_activation() {
        assert_eq!(super::locktime_cutoff(true, 500, 999), 500);
        assert_eq!(super::locktime_cutoff(false, 500, 999), 999);
    }
}

pub use block_view::{BlockFacts, BlockView};
pub use engine::ValidationEngine;
pub use sigops::transaction_sigop_cost;
pub use verify_block::{
    BlockRuleContext, MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_WEIGHT, check_block_body_binding,
    compute_merkle_root, verify_block_rules, verify_block_rules_precomputed, verify_flags,
    verify_merkle_root_with_txids,
};
pub use verify_tx::{
    ScriptStageTimings, check_coinbase_maturity, is_final_tx, verify_block_input_scripts,
    verify_coinbase_script_sig_size, verify_transaction, verify_transaction_non_script,
};

use bitcoin_rs_primitives::{OutPoint, TxOut};
use thiserror::Error;

/// Lookup returns the referenced coin or None when absent; borrowed views agree.
pub trait UtxoView {
    /// Looks up a previous output by outpoint.
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut>;
}

/// The engine that rejected a script.
/// Kernel rejections are retryable; native rejections are consensus-final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptEngine {
    /// Bitcoin Core's `bitcoinkernel` C++ engine (the `kernel` feature).
    Kernel,
    /// The portable Rust interpreter in `bitcoin-rs-script`.
    Native,
}

/// Consensus validation error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("transaction has no inputs")]
    EmptyInputs,
    #[error("transaction has no outputs")]
    EmptyOutputs,
    #[error("coinbase scriptSig length {len} outside allowed range 2..=100 bytes")]
    CoinbaseScriptSigSize { len: usize },
    #[error("non-coinbase transaction input {input_index} spends a null outpoint")]
    NullPrevout { input_index: usize },
    #[error("transaction contains duplicate input {input_index}")]
    DuplicateInput { input_index: usize },
    #[error("missing prevout for input {input_index}")]
    MissingPrevout { input_index: usize },
    #[error("transaction output value exceeds max money")]
    OutputValueOverflow,
    #[error("transaction spends {input_value} sats but creates {output_value} sats")]
    InputsLessThanOutputs { input_value: u64, output_value: u64 },
    #[error("script verification failed at input {input_index}: {reason}")]
    Script {
        input_index: usize,
        reason: String,
        engine: ScriptEngine,
    },
    #[error("sigop cost {cost} exceeds max {max}")]
    SigopsLimit { cost: u32, max: u32 },
    #[error("block has no transactions")]
    EmptyBlock,
    #[error("block first transaction is not coinbase")]
    MissingCoinbase,
    #[error("block transaction {tx_index} is coinbase outside position 0")]
    ExtraCoinbase { tx_index: usize },
    #[error("block merkle tree contains a duplicate transaction mutation")]
    MerkleMutation,
    #[error("block merkle root mismatch")]
    MerkleRoot,
    #[error("coinbase pays {paid} sats but only {allowed} sats are available")]
    CoinbaseAmount { paid: u64, allowed: u64 },
    #[error("block value total overflows the satoshi range")]
    BlockValueOverflow,
    #[error("coinbase witness reserved nonce is missing or the wrong size")]
    WitnessNonceSize,
    #[error("unexpected witness data")]
    UnexpectedWitness,
    #[error("block witness commitment mismatch")]
    WitnessCommitment,
    #[error("block weight {weight} exceeds max {max}")]
    BlockWeight { weight: u64, max: u64 },
    #[error("{bip}: {reason}")]
    Bip { bip: &'static str, reason: String },
    #[error("block prevout matrix has {actual} rows for {expected} transactions")]
    PrevoutMatrixSize { expected: usize, actual: usize },
    #[error("transaction has {input_count} inputs but {prevout_count} prevouts")]
    PrevoutCount {
        input_count: usize,
        prevout_count: usize,
    },
    #[error("prevout does not match transaction input {input_index}")]
    PrevoutMismatch { input_index: usize },
    #[error("unsupported validation engine: {engine}")]
    UnsupportedEngine { engine: ValidationEngine },
    #[error("kernel validation failed: {0}")]
    Kernel(String),
    #[error("consensus encoding failed: {0}")]
    Encoding(String),
}

/// Coinbase subsidy at `height`, in satoshis.
#[must_use]
pub const fn block_subsidy(height: u32, halving_interval: u32) -> u64 {
    const INITIAL_SUBSIDY_SATS: u64 = 50 * 100_000_000;

    if halving_interval == 0 {
        return INITIAL_SUBSIDY_SATS;
    }
    let halvings = height / halving_interval;
    // Core stops at 64 shifts; past that the subsidy is zero and shifting a
    // u64 by 64 or more is undefined.
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY_SATS >> halvings
}

/// Verifies that a block's coinbase claims no more than it earned.
pub const fn verify_coinbase_amount(
    coinbase_out: u64,
    fees: u64,
    height: u32,
    halving_interval: u32,
) -> Result<(), ConsensusError> {
    let Some(allowed) = block_subsidy(height, halving_interval).checked_add(fees) else {
        return Err(ConsensusError::BlockValueOverflow);
    };
    if coinbase_out > allowed {
        return Err(ConsensusError::CoinbaseAmount {
            paid: coinbase_out,
            allowed,
        });
    }
    Ok(())
}

/// Maximum block sigop cost after segwit scaling.
pub const MAX_BLOCK_SIGOPS_COST: u32 = 80_000;
