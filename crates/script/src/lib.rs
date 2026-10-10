//! Script verification, sigop counting, and native script utilities.
//!
//! The interpreter executes every consensus spend class natively: legacy and
//! P2SH through the opcode evaluator, `SegWit` v0 through BIP143 sighashes,
//! and taproot key-path and script-path spends through local BIP341/BIP342
//! verification.

#![forbid(unsafe_op_in_unsafe_fn)]

/// Transaction signature checker: ECDSA, Schnorr, locktime, and sequence verification.
mod checker;
/// The opcode evaluator: the bounded stack machine behind the interpreter.
mod eval;
/// Script verification wrapper.
mod interpreter;
/// Native script parsing, classification, and building helpers.
mod script;
/// Signature operation counters.
pub mod sigops;
/// Bounded script stack with Core's 1000-item maximum depth.
mod stack;
/// Taproot verification helpers.
mod taproot;

pub use checker::check_signature_encoding;
pub use eval::{MAX_SCRIPT_SIZE, is_op_success};
pub use interpreter::{
    Interpreter, PreparedTransaction, PrevoutError, ScriptErrCode, ScriptError, VerifyFlags,
    validate_prevouts,
};
pub use script::{
    EarlyEndOfScript, Instruction, Instructions, has_valid_ops, instructions, is_multisig,
    is_op_return, is_p2a, is_p2pk, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh, is_push_only,
    is_witness_program, minimal_non_dust, multisig_key_count, opcode, push_data, push_int,
    witness_program,
};
pub use sigops::{count_segwit, count_tx_legacy};
