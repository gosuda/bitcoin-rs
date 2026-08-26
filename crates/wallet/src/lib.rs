#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

//! Watch-only wallet primitives.
//!
//! # Safety note: watch-only, no custody
//!
//! This crate is watch-only. It parses public descriptors, builds unsigned
//! PSBTs, accepts PSBTs returned by external signers, and finalizes those
//! PSBTs. It never generates, stores, or derives secret keys, and it rejects
//! private material on descriptor import. The only secret material it touches
//! is caller-supplied keys passed to a single `signer_iface` call; those keys
//! are used for that call and immediately dropped.

/// Coin selection wrappers.
pub mod coin_selection;
/// Output descriptor support.
pub mod descriptor;
/// Replace-by-fee helpers.
pub mod fee_bump;
/// Signed PSBT finalization.
pub mod finalize;
/// PSBT construction.
pub mod psbt;
/// External signer interface.
pub mod signer_iface;
/// Descriptor watcher.
pub mod watcher;

pub use coin_selection::{Candidate, SelectStrategy, Selection, Target, select_coins};
pub use descriptor::{BIP32Derivation, Descriptor, DescriptorInfo, analyse};
pub use fee_bump::{FeeBumpPlan, bump_fee, bump_psbt, bump_psbt_with_rate_sat_per_kvb};
pub use finalize::{FinalizeError, finalize_psbt, finalize_signed};
pub use psbt::{PrevUtxo, PsbtBuilder};
pub use signer_iface::{
    ExternalSigner, SignerError, sign_psbt_with_caller_keys, sign_psbt_with_explicit_prevouts,
};
pub use watcher::{DescriptorImport, DescriptorTimestamp, Watcher};

use thiserror::Error;

/// Wallet crate error.
#[derive(Debug, Error)]
pub enum WalletError {
    /// Descriptor parsing or derivation failed.
    #[error("descriptor error: {0}")]
    Descriptor(String),
    /// The descriptor contains private key material.
    #[error("descriptor contains private key material")]
    PrivateDescriptor,
    /// A derivation range was required, forbidden, or empty.
    #[error("{0}")]
    DescriptorRange(&'static str),
    /// PSBT construction failed.
    #[error("psbt error: {0}")]
    Psbt(String),
    /// Coin selection could not fund the target.
    #[error("insufficient funds: missing {missing} sats")]
    InsufficientFunds {
        /// Missing amount in satoshis.
        missing: u64,
    },
    /// No branch-and-bound solution was found before the round limit.
    #[error("no branch-and-bound solution after {rounds} of {max_rounds} rounds")]
    NoBnbSolution {
        /// Rounds completed.
        rounds: usize,
        /// Configured maximum rounds.
        max_rounds: usize,
    },
    /// The transaction is not known to this watch-only wallet state.
    #[error("transaction {txid} is not available for fee bumping")]
    MissingTransaction {
        /// Missing transaction id.
        txid: bitcoin::Txid,
    },
    /// The requested replacement does not satisfy BIP125 rules.
    #[error("replacement violates BIP125: {0}")]
    Bip125(String),
    /// Finalization failed.
    #[error(transparent)]
    Finalize(#[from] FinalizeError),
    /// Durable watch-only state could not be encoded or decoded.
    #[error("wallet state error: {0}")]
    State(String),
}
