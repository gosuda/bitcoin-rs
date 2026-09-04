//! Script verification, sigop counting, and native script utilities.
//!
//! The interpreter executes every consensus spend class natively: legacy and
//! P2SH through the opcode evaluator, `SegWit` v0 through BIP143 sighashes,
//! and taproot key-path and script-path spends through local BIP341/BIP342
//! verification.

#![forbid(unsafe_op_in_unsafe_fn)]

/// Rayon-backed Schnorr verification helpers.
pub mod batch;
/// Transaction signature checker: ECDSA, Schnorr, locktime, and sequence verification.
pub mod checker;
/// The opcode evaluator: the bounded stack machine behind the interpreter.
pub mod eval;
/// Script verification wrapper.
pub mod interpreter;
/// Native script parsing, classification, and building helpers.
pub mod script;
/// Signature operation counters.
pub mod sigops;
/// Bounded script stack with Core's 1000-item maximum depth.
pub mod stack;
/// Taproot verification helpers.
pub mod taproot;

pub use interpreter::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};
pub use script::{
    EarlyEndOfScript, Instruction, Instructions, is_multisig, is_op_return, is_p2a, is_p2pk,
    is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh, is_push_only, is_witness_program,
    minimal_non_dust, opcode, p2pk_pubkey_bytes, push_data, push_int, witness_program,
};
pub use sigops::{count_block, count_legacy, count_segwit, count_taproot, count_tx_legacy};
pub use stack::{ScriptItem, Stack, StackError};
