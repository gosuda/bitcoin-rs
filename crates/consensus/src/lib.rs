//! Consensus validation surfaces for bitcoin-rs.
//!
//! The `kernel` feature is the production default: it routes every script class
//! through bitcoinkernel (Bitcoin Core's native consensus engine). With the
//! feature off, the crate builds a portable Rust validation path that delegates
//! taproot key-path script execution to `bitcoin-rs-script` and keeps
//! consensus-facing rule checks in small, testable modules. The portable path
//! is retained for differential tests and builds without a native backend.

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
/// Non-terminal CHECKSIG census checkpoint ABI wrapper.
#[cfg(feature = "checksig-census")]
pub mod census_checkpoint;
/// Dual-path block connection.
pub mod connect_block;
/// Feature-gated bitcoinkernel wrapper.
pub mod kernel;
/// Portable Rust validator.
pub mod rust_path;
/// Private AVX2 SHA256d64 kernel for Merkle hashing.
mod sha256d64;
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
    verify_block_rules_contextual, verify_merkle_root_with_txids,
};
pub use verify_tx::{
    ScriptStageTimings, is_final_tx, verify_block_input_scripts, verify_coinbase_script_sig_size,
    verify_transaction, verify_transaction_borrowed,
    verify_transaction_borrowed_non_script_with_mtp, verify_transaction_borrowed_with_mtp,
    verify_transaction_with_mtp,
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
    /// The coinbase claims more than the subsidy plus the fees the block earned.
    ///
    /// Bitcoin Core's `bad-cb-amount`. Nothing else bounds what a coinbase may
    /// pay itself, so this is the rule that keeps a miner from creating money.
    #[error("coinbase pays {paid} sats but only {allowed} sats are available")]
    CoinbaseAmount {
        /// Total value the coinbase outputs claim.
        paid: u64,
        /// Block subsidy plus the fees of the block's other transactions.
        allowed: u64,
    },
    /// Summing a block's values overflowed the satoshi range.
    #[error("block value total overflows the satoshi range")]
    BlockValueOverflow,
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
    /// Block-level verification received the wrong number of prevout rows.
    #[error("block prevout matrix has {actual} rows for {expected} transactions")]
    PrevoutMatrixSize {
        /// Number of block transactions that require rows.
        expected: usize,
        /// Number of supplied prevout rows.
        actual: usize,
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

/// Coinbase subsidy at `height`, in satoshis.
///
/// Bitcoin Core's `GetBlockSubsidy`. `halving_interval` comes from the network
/// (`Network::subsidy_halving_interval`) rather than being fixed at 210 000,
/// because regtest halves every 150 blocks — hard-coding the mainnet interval
/// would compute the wrong subsidy on the one network where a halving is
/// reachable in a test.
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
///
/// `fees` is the sum over the block's non-coinbase transactions of input value
/// minus output value; `coinbase_out` is what the coinbase pays itself. Core
/// applies this in `ConnectBlock` and rejects with `bad-cb-amount`.
///
/// Paying *less* than the maximum is allowed, as it is in Core — the
/// difference is simply destroyed.
///
/// # Errors
///
/// Returns [`ConsensusError::CoinbaseAmount`] when the coinbase claims more
/// than the subsidy plus `fees`, or [`ConsensusError::BlockValueOverflow`] if
/// that sum leaves the satoshi range.
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
