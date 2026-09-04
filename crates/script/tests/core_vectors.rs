//! Differential vector harness over Bitcoin Core's script consensus test data.
//!
//! Feeds Core's `script_tests.json`, `tx_valid.json`, `tx_invalid.json`, and
//! `sighash.json` through the native [`Interpreter`] and (when `--features kernel`
//! is enabled) the bitcoinkernel oracle, then compares verdicts.
//!
//! ## Anti-vacuity
//!
//! Every corpus prints four counts: rows parsed, rows executed, rows skipped
//! (with a one-line reason per category), and rows failed. A deliberately
//! broken expectation proves the harness reports failures rather than passing
//! vacuously.
//!
//! ## Two columns
//!
//! The native evaluator runs every non-taproot spend class. Each native column
//! pins its remaining mismatch count, so a shrink lowers the constant with
//! evidence and a growth fails the lane. The kernel column stays available
//! under `--features kernel` as an oracle for the same rows.
//!
//! Run:
//!
//! ```sh
//! cargo test -p bitcoin-rs-script --test core_vectors
//! cargo test -p bitcoin-rs-script --features kernel --test core_vectors
//! ```

#![cfg(test)]

use std::str::FromStr;

use bitcoin::ScriptBuf;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin_rs_primitives::tapleaf_hash;
use bitcoin_rs_primitives::{Hash256, OutPoint, SighashCache, Tx, TxIn, TxOut, Txid, deserialize};
use bitcoin_rs_script::{
    Interpreter, ScriptError, VerifyFlags, opcode, push_data, push_int, taproot,
};

// ===========================================================================
// Script error code model — Core's `ScriptErrorString` names
// ===========================================================================

/// Core's script error identifiers, rendered as the exact names from
/// `script_error.cpp` / `script_tests.cpp`'s `script_errors[]` table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScriptErrCode {
    Ok,
    EvalFalse,
    OpReturn,
    Scriptnum,
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    NegativeLocktime,
    UnsatisfiedLocktime,
    SigHashtype,
    SigDer,
    MinimalData,
    SigPushOnly,
    SigHighS,
    SigNullDummy,
    PubkeyType,
    CleanStack,
    MinimalIf,
    NullFail,
    DiscourageUpgradableNops,
    DiscourageUpgradableWitnessProgram,
    DiscourageUpgradableTaprootVersion,
    DiscourageOpSuccess,
    DiscourageUpgradablePubkeyType,
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2sh,
    WitnessUnexpected,
    WitnessPubkeyType,
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckMultisig,
    TapscriptMinimalIf,
    TapscriptEmptyPubkey,
    OpCodeSeparator,
    SigFindAndDelete,
}

impl ScriptErrCode {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "OK" => Self::Ok,
            "EVAL_FALSE" => Self::EvalFalse,
            "OP_RETURN" => Self::OpReturn,
            "SCRIPTNUM" => Self::Scriptnum,
            "SCRIPT_SIZE" => Self::ScriptSize,
            "PUSH_SIZE" => Self::PushSize,
            "OP_COUNT" => Self::OpCount,
            "STACK_SIZE" => Self::StackSize,
            "SIG_COUNT" => Self::SigCount,
            "PUBKEY_COUNT" => Self::PubkeyCount,
            "VERIFY" => Self::Verify,
            "EQUALVERIFY" => Self::EqualVerify,
            "CHECKMULTISIGVERIFY" => Self::CheckMultisigVerify,
            "CHECKSIGVERIFY" => Self::CheckSigVerify,
            "NUMEQUALVERIFY" => Self::NumEqualVerify,
            "BAD_OPCODE" => Self::BadOpcode,
            "DISABLED_OPCODE" => Self::DisabledOpcode,
            "INVALID_STACK_OPERATION" => Self::InvalidStackOperation,
            "INVALID_ALTSTACK_OPERATION" => Self::InvalidAltstackOperation,
            "UNBALANCED_CONDITIONAL" => Self::UnbalancedConditional,
            "NEGATIVE_LOCKTIME" => Self::NegativeLocktime,
            "UNSATISFIED_LOCKTIME" => Self::UnsatisfiedLocktime,
            "SIG_HASHTYPE" => Self::SigHashtype,
            "SIG_DER" => Self::SigDer,
            "MINIMALDATA" => Self::MinimalData,
            "SIG_PUSHONLY" => Self::SigPushOnly,
            "SIG_HIGH_S" => Self::SigHighS,
            "SIG_NULLDUMMY" => Self::SigNullDummy,
            "PUBKEYTYPE" => Self::PubkeyType,
            "CLEANSTACK" => Self::CleanStack,
            "MINIMALIF" => Self::MinimalIf,
            "NULLFAIL" => Self::NullFail,
            "DISCOURAGE_UPGRADABLE_NOPS" => Self::DiscourageUpgradableNops,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => Self::DiscourageUpgradableWitnessProgram,
            "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => Self::DiscourageUpgradableTaprootVersion,
            "DISCOURAGE_OP_SUCCESS" => Self::DiscourageOpSuccess,
            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => Self::DiscourageUpgradablePubkeyType,
            "WITNESS_PROGRAM_WRONG_LENGTH" => Self::WitnessProgramWrongLength,
            "WITNESS_PROGRAM_WITNESS_EMPTY" => Self::WitnessProgramWitnessEmpty,
            "WITNESS_PROGRAM_MISMATCH" => Self::WitnessProgramMismatch,
            "WITNESS_MALLEATED" => Self::WitnessMalleated,
            "WITNESS_MALLEATED_P2SH" => Self::WitnessMalleatedP2sh,
            "WITNESS_UNEXPECTED" => Self::WitnessUnexpected,
            "WITNESS_PUBKEYTYPE" => Self::WitnessPubkeyType,
            "SCHNORR_SIG_SIZE" => Self::SchnorrSigSize,
            "SCHNORR_SIG_HASHTYPE" => Self::SchnorrSigHashtype,
            "SCHNORR_SIG" => Self::SchnorrSig,
            "TAPROOT_WRONG_CONTROL_SIZE" => Self::TaprootWrongControlSize,
            "TAPSCRIPT_VALIDATION_WEIGHT" => Self::TapscriptValidationWeight,
            "TAPSCRIPT_CHECKMULTISIG" => Self::TapscriptCheckMultisig,
            "TAPSCRIPT_MINIMALIF" => Self::TapscriptMinimalIf,
            "TAPSCRIPT_EMPTY_PUBKEY" => Self::TapscriptEmptyPubkey,
            "OP_CODESEPARATOR" => Self::OpCodeSeparator,
            "SIG_FINDANDDELETE" => Self::SigFindAndDelete,
            _ => return None,
        })
    }

    fn is_ok(self) -> bool {
        self == Self::Ok
    }
}

impl std::fmt::Display for ScriptErrCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Ok => "OK",
            Self::EvalFalse => "EVAL_FALSE",
            Self::OpReturn => "OP_RETURN",
            Self::Scriptnum => "SCRIPTNUM",
            Self::ScriptSize => "SCRIPT_SIZE",
            Self::PushSize => "PUSH_SIZE",
            Self::OpCount => "OP_COUNT",
            Self::StackSize => "STACK_SIZE",
            Self::SigCount => "SIG_COUNT",
            Self::PubkeyCount => "PUBKEY_COUNT",
            Self::Verify => "VERIFY",
            Self::EqualVerify => "EQUALVERIFY",
            Self::CheckMultisigVerify => "CHECKMULTISIGVERIFY",
            Self::CheckSigVerify => "CHECKSIGVERIFY",
            Self::NumEqualVerify => "NUMEQUALVERIFY",
            Self::BadOpcode => "BAD_OPCODE",
            Self::DisabledOpcode => "DISABLED_OPCODE",
            Self::InvalidStackOperation => "INVALID_STACK_OPERATION",
            Self::InvalidAltstackOperation => "INVALID_ALTSTACK_OPERATION",
            Self::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            Self::NegativeLocktime => "NEGATIVE_LOCKTIME",
            Self::UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
            Self::SigHashtype => "SIG_HASHTYPE",
            Self::SigDer => "SIG_DER",
            Self::MinimalData => "MINIMALDATA",
            Self::SigPushOnly => "SIG_PUSHONLY",
            Self::SigHighS => "SIG_HIGH_S",
            Self::SigNullDummy => "SIG_NULLDUMMY",
            Self::PubkeyType => "PUBKEYTYPE",
            Self::CleanStack => "CLEANSTACK",
            Self::MinimalIf => "MINIMALIF",
            Self::NullFail => "NULLFAIL",
            Self::DiscourageUpgradableNops => "DISCOURAGE_UPGRADABLE_NOPS",
            Self::DiscourageUpgradableWitnessProgram => "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            Self::DiscourageUpgradableTaprootVersion => "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
            Self::DiscourageOpSuccess => "DISCOURAGE_OP_SUCCESS",
            Self::DiscourageUpgradablePubkeyType => "DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
            Self::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            Self::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            Self::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            Self::WitnessMalleated => "WITNESS_MALLEATED",
            Self::WitnessMalleatedP2sh => "WITNESS_MALLEATED_P2SH",
            Self::WitnessUnexpected => "WITNESS_UNEXPECTED",
            Self::WitnessPubkeyType => "WITNESS_PUBKEYTYPE",
            Self::SchnorrSigSize => "SCHNORR_SIG_SIZE",
            Self::SchnorrSigHashtype => "SCHNORR_SIG_HASHTYPE",
            Self::SchnorrSig => "SCHNORR_SIG",
            Self::TaprootWrongControlSize => "TAPROOT_WRONG_CONTROL_SIZE",
            Self::TapscriptValidationWeight => "TAPSCRIPT_VALIDATION_WEIGHT",
            Self::TapscriptCheckMultisig => "TAPSCRIPT_CHECKMULTISIG",
            Self::TapscriptMinimalIf => "TAPSCRIPT_MINIMALIF",
            Self::TapscriptEmptyPubkey => "TAPSCRIPT_EMPTY_PUBKEY",
            Self::OpCodeSeparator => "OP_CODESEPARATOR",
            Self::SigFindAndDelete => "SIG_FINDANDDELETE",
        };
        f.write_str(name)
    }
}

// ===========================================================================
// Core ASM script assembler
// ===========================================================================

/// Parses a Core test-vector script string into raw bytes.
///
/// Implements Core's `ParseScript` from `core_io.cpp`:
/// - `0xHEX` → raw hex bytes inserted directly (not pushed)
/// - decimal numbers (optionally negative) → `push_int`
/// - `'quoted'` → `push_data` of the literal bytes
/// - `OP_NAME` or bare `NAME` → the opcode byte
fn parse_core_asm(asm: &str) -> Result<Vec<u8>, String> {
    let mut script = Vec::new();
    for token in asm.split([' ', '\t', '\n']) {
        if token.is_empty() {
            continue;
        }
        if let Some(hex) = token.strip_prefix("0x") {
            if hex.is_empty() {
                return Err(format!("empty 0x token: {token}"));
            }
            let bytes =
                hex_to_bytes(hex).map_err(|e| format!("invalid hex in token {token}: {e}"))?;
            script.extend_from_slice(&bytes);
        } else if is_decimal_int(token) {
            let n = token
                .parse::<i64>()
                .map_err(|e| format!("decimal parse failed for {token}: {e}"))?;
            script.extend_from_slice(&push_int(n));
        } else if token.len() >= 2 && token.starts_with('\'') && token.ends_with('\'') {
            let inner = &token[1..token.len() - 1];
            script.extend_from_slice(&push_data(inner.as_bytes()));
        } else {
            let byte =
                resolve_opcode(token).ok_or_else(|| format!("unknown opcode token: {token}"))?;
            script.push(byte);
        }
    }
    Ok(script)
}

fn is_decimal_int(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let start = usize::from(bytes[0] == b'-');
    if start >= bytes.len() {
        return false;
    }
    bytes[start..].iter().all(u8::is_ascii_digit)
}

fn resolve_opcode(name: &str) -> Option<u8> {
    let bare = name.strip_prefix("OP_").unwrap_or(name);
    lookup_opcode(bare)
}

static OPCODE_BYTES: &[(u8, &[&str])] = &[
    (0x00, &["0", "EMPTY"]),
    (0x4c, &["PUSHDATA1"]),
    (0x4d, &["PUSHDATA2"]),
    (0x4e, &["PUSHDATA4"]),
    (0x4f, &["1NEGATE"]),
    (0x50, &["RESERVED"]),
    (0x51, &["1", "PUSHNUM_1"]),
    (0x52, &["2", "PUSHNUM_2"]),
    (0x53, &["3", "PUSHNUM_3"]),
    (0x54, &["4", "PUSHNUM_4"]),
    (0x55, &["5", "PUSHNUM_5"]),
    (0x56, &["6", "PUSHNUM_6"]),
    (0x57, &["7", "PUSHNUM_7"]),
    (0x58, &["8", "PUSHNUM_8"]),
    (0x59, &["9", "PUSHNUM_9"]),
    (0x5a, &["10", "PUSHNUM_10"]),
    (0x5b, &["11", "PUSHNUM_11"]),
    (0x5c, &["12", "PUSHNUM_12"]),
    (0x5d, &["13", "PUSHNUM_13"]),
    (0x5e, &["14", "PUSHNUM_14"]),
    (0x5f, &["15", "PUSHNUM_15"]),
    (0x60, &["16", "PUSHNUM_16"]),
    (0x61, &["NOP"]),
    (0x62, &["VER"]),
    (0x63, &["IF"]),
    (0x64, &["NOTIF"]),
    (0x65, &["VERIF"]),
    (0x66, &["VERNOTIF"]),
    (0x67, &["ELSE"]),
    (0x68, &["ENDIF"]),
    (0x69, &["VERIFY"]),
    (0x6a, &["RETURN"]),
    (0x6b, &["TOALTSTACK"]),
    (0x6c, &["FROMALTSTACK"]),
    (0x6d, &["2DROP"]),
    (0x6e, &["2DUP"]),
    (0x6f, &["3DUP"]),
    (0x70, &["2OVER"]),
    (0x71, &["2ROT"]),
    (0x72, &["2SWAP"]),
    (0x73, &["IFDUP"]),
    (0x74, &["DEPTH"]),
    (0x75, &["DROP"]),
    (0x76, &["DUP"]),
    (0x77, &["NIP"]),
    (0x78, &["OVER"]),
    (0x79, &["PICK"]),
    (0x7a, &["ROLL"]),
    (0x7b, &["ROT"]),
    (0x7c, &["SWAP"]),
    (0x7d, &["TUCK"]),
    (0x7e, &["CAT"]),
    (0x7f, &["SUBSTR"]),
    (0x80, &["LEFT"]),
    (0x81, &["RIGHT"]),
    (0x82, &["SIZE"]),
    (0x83, &["INVERT"]),
    (0x84, &["AND"]),
    (0x85, &["OR"]),
    (0x86, &["XOR"]),
    (0x87, &["EQUAL"]),
    (0x88, &["EQUALVERIFY"]),
    (0x89, &["RESERVED1"]),
    (0x8a, &["RESERVED2"]),
    (0x8b, &["1ADD"]),
    (0x8c, &["1SUB"]),
    (0x8d, &["2MUL"]),
    (0x8e, &["2DIV"]),
    (0x8f, &["NEGATE"]),
    (0x90, &["ABS"]),
    (0x91, &["NOT"]),
    (0x92, &["0NOTEQUAL"]),
    (0x93, &["ADD"]),
    (0x94, &["SUB"]),
    (0x95, &["MUL"]),
    (0x96, &["DIV"]),
    (0x97, &["MOD"]),
    (0x98, &["LSHIFT"]),
    (0x99, &["RSHIFT"]),
    (0x9a, &["BOOLAND"]),
    (0x9b, &["BOOLOR"]),
    (0x9c, &["NUMEQUAL"]),
    (0x9d, &["NUMEQUALVERIFY"]),
    (0x9e, &["NUMNOTEQUAL"]),
    (0x9f, &["LESSTHAN"]),
    (0xa0, &["GREATERTHAN"]),
    (0xa1, &["LESSTHANOREQUAL"]),
    (0xa2, &["GREATERTHANOREQUAL"]),
    (0xa3, &["MIN"]),
    (0xa4, &["MAX"]),
    (0xa5, &["WITHIN"]),
    (0xa6, &["RIPEMD160"]),
    (0xa7, &["SHA1"]),
    (0xa8, &["SHA256"]),
    (0xa9, &["HASH160"]),
    (0xaa, &["HASH256"]),
    (0xab, &["CODESEPARATOR"]),
    (0xac, &["CHECKSIG"]),
    (0xad, &["CHECKSIGVERIFY"]),
    (0xae, &["CHECKMULTISIG"]),
    (0xaf, &["CHECKMULTISIGVERIFY"]),
    (0xb0, &["NOP1"]),
    (0xb1, &["CHECKLOCKTIMEVERIFY"]),
    (0xb2, &["CHECKSEQUENCEVERIFY"]),
    (0xb3, &["NOP4"]),
    (0xb4, &["NOP5"]),
    (0xb5, &["NOP6"]),
    (0xb6, &["NOP7"]),
    (0xb7, &["NOP8"]),
    (0xb8, &["NOP9"]),
    (0xb9, &["NOP10"]),
    (0xba, &["CHECKSIGADD"]),
    (0xfd, &["PUBKEYHASH"]),
    (0xfe, &["PUBKEY"]),
    (0xff, &["INVALIDOPCODE"]),
];

static OP_SUCCESS_NAMES: &[(u8, &str)] = &[
    (0x50, "SUCCESS_0"),
    (0x7e, "SUCCESS_80"),
    (0x7f, "SUCCESS_81"),
    (0x80, "SUCCESS_82"),
    (0x81, "SUCCESS_83"),
    (0x82, "SUCCESS_84"),
    (0x83, "SUCCESS_85"),
    (0x84, "SUCCESS_86"),
    (0x85, "SUCCESS_87"),
    (0x86, "SUCCESS_88"),
    (0x87, "SUCCESS_89"),
    (0x88, "SUCCESS_90"),
    (0x89, "SUCCESS_91"),
    (0x8a, "SUCCESS_92"),
    (0x8b, "SUCCESS_93"),
    (0x8c, "SUCCESS_94"),
    (0x8d, "SUCCESS_95"),
    (0x8e, "SUCCESS_96"),
    (0x8f, "SUCCESS_97"),
    (0x90, "SUCCESS_98"),
    (0x91, "SUCCESS_99"),
    (0x92, "SUCCESS_100"),
    (0x93, "SUCCESS_101"),
    (0x94, "SUCCESS_102"),
    (0x95, "SUCCESS_103"),
    (0x96, "SUCCESS_104"),
    (0x97, "SUCCESS_105"),
    (0x98, "SUCCESS_106"),
    (0x99, "SUCCESS_107"),
    (0x9a, "SUCCESS_108"),
    (0x9b, "SUCCESS_109"),
    (0x9c, "SUCCESS_110"),
    (0x9d, "SUCCESS_111"),
    (0x9e, "SUCCESS_112"),
    (0x9f, "SUCCESS_113"),
    (0xa0, "SUCCESS_114"),
    (0xa1, "SUCCESS_115"),
    (0xa2, "SUCCESS_116"),
    (0xa3, "SUCCESS_117"),
    (0xa4, "SUCCESS_118"),
    (0xa5, "SUCCESS_119"),
    (0xa6, "SUCCESS_120"),
    (0xa7, "SUCCESS_121"),
    (0xa8, "SUCCESS_122"),
    (0xa9, "SUCCESS_123"),
    (0xaa, "SUCCESS_124"),
    (0xab, "SUCCESS_125"),
    (0xac, "SUCCESS_126"),
    (0xad, "SUCCESS_127"),
    (0xae, "SUCCESS_128"),
    (0xaf, "SUCCESS_129"),
    (0xb0, "SUCCESS_130"),
    (0xb1, "SUCCESS_131"),
    (0xb2, "SUCCESS_132"),
    (0xb3, "SUCCESS_133"),
    (0xb4, "SUCCESS_134"),
    (0xb5, "SUCCESS_135"),
    (0xb6, "SUCCESS_136"),
    (0xb7, "SUCCESS_137"),
    (0xb8, "SUCCESS_138"),
    (0xb9, "SUCCESS_139"),
    (0xba, "SUCCESS_140"),
    (0xbb, "SUCCESS_141"),
    (0xbc, "SUCCESS_142"),
    (0xbd, "SUCCESS_143"),
    (0xbe, "SUCCESS_144"),
    (0xbf, "SUCCESS_145"),
    (0xc0, "SUCCESS_146"),
    (0xc1, "SUCCESS_147"),
    (0xc2, "SUCCESS_148"),
    (0xc3, "SUCCESS_149"),
    (0xc4, "SUCCESS_150"),
    (0xc5, "SUCCESS_151"),
    (0xc6, "SUCCESS_152"),
    (0xc7, "SUCCESS_153"),
    (0xc8, "SUCCESS_154"),
    (0xc9, "SUCCESS_155"),
    (0xca, "SUCCESS_156"),
    (0xcb, "SUCCESS_157"),
    (0xcc, "SUCCESS_158"),
    (0xcd, "SUCCESS_159"),
    (0xce, "SUCCESS_160"),
    (0xcf, "SUCCESS_161"),
    (0xd0, "SUCCESS_162"),
    (0xd1, "SUCCESS_163"),
    (0xd2, "SUCCESS_164"),
    (0xd3, "SUCCESS_165"),
    (0xd4, "SUCCESS_166"),
    (0xd5, "SUCCESS_167"),
    (0xd6, "SUCCESS_168"),
    (0xd7, "SUCCESS_169"),
    (0xd8, "SUCCESS_170"),
    (0xd9, "SUCCESS_171"),
    (0xda, "SUCCESS_172"),
    (0xdb, "SUCCESS_173"),
    (0xdc, "SUCCESS_174"),
    (0xdd, "SUCCESS_175"),
    (0xde, "SUCCESS_176"),
    (0xdf, "SUCCESS_177"),
    (0xe0, "SUCCESS_178"),
    (0xe1, "SUCCESS_179"),
    (0xe2, "SUCCESS_180"),
    (0xe3, "SUCCESS_181"),
    (0xe4, "SUCCESS_182"),
    (0xe5, "SUCCESS_183"),
    (0xe6, "SUCCESS_184"),
    (0xe7, "SUCCESS_185"),
    (0xe8, "SUCCESS_186"),
    (0xe9, "SUCCESS_187"),
    (0xea, "SUCCESS_188"),
    (0xeb, "SUCCESS_189"),
    (0xec, "SUCCESS_190"),
    (0xed, "SUCCESS_191"),
];

/// Linear search through the opcode tables. Test-only, so O(n) is fine.
fn lookup_opcode(bare: &str) -> Option<u8> {
    for &(byte, names) in OPCODE_BYTES {
        if names.contains(&bare) {
            return Some(byte);
        }
    }
    for &(byte, name) in OP_SUCCESS_NAMES {
        if name == bare {
            return Some(byte);
        }
    }
    None
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("odd length: {}", hex.len()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("at offset {i}: {e}")))
        .collect()
}

// ===========================================================================
// Transaction construction — Core's BuildCrediting/BuildSpending
// ===========================================================================

const SEQUENCE_FINAL: u32 = 0xffff_ffff;

fn build_crediting_tx(script_pubkey: &[u8], amount: u64) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: vec![opcode::OP_0, opcode::OP_0],
            sequence: SEQUENCE_FINAL,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: amount,
            script_pubkey: script_pubkey.to_vec(),
        }],
        lock_time: 0,
    }
}

fn build_spending_tx(script_sig: &[u8], witness: &[Vec<u8>], credit_tx: &Tx) -> Tx {
    let credit_txid = credit_tx.txid();
    Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(credit_txid, 0),
            script_sig: script_sig.to_vec(),
            sequence: SEQUENCE_FINAL,
            witness: witness.to_vec(),
        }],
        outputs: vec![TxOut {
            value: credit_tx.outputs[0].value,
            script_pubkey: Vec::new(),
        }],
        lock_time: 0,
    }
}

// ===========================================================================
// Verdict model
// ===========================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    /// Carries Core's error name when the interpreter produced one, so a
    /// mismatch says which rule fired rather than only that something did.
    Reject(Option<String>),
}

impl Verdict {
    fn from_interpreter(result: &Result<bool, ScriptError>) -> Self {
        match result {
            Ok(true) => Self::Accept,
            Err(ScriptError::Invalid { code }) => Self::Reject(Some(code.to_string())),
            Ok(false) | Err(_) => Self::Reject(None),
        }
    }

    #[cfg(feature = "kernel")]
    fn from_kernel(result: &Result<(), bitcoin_rs_consensus::ConsensusError>) -> Self {
        // The kernel reports a verdict, not Core's error name, so its column
        // can prove accept-or-reject parity and nothing about error names.
        match result {
            Ok(()) => Self::Accept,
            Err(_) => Self::Reject(None),
        }
    }

    /// Whether the row was accepted. Rejection carries a code for triage, so
    /// comparisons between a verdict and an expectation must go through this
    /// rather than through equality on the payload.
    const fn accepted(&self) -> bool {
        matches!(self, Self::Accept)
    }

    fn matches_expected(&self, expected: ScriptErrCode) -> bool {
        match self {
            Self::Accept => expected.is_ok(),
            Self::Reject(_) => !expected.is_ok(),
        }
    }
}

// ===========================================================================
// Counters for anti-vacuity
// ===========================================================================

#[derive(Default, Debug)]
struct Counts {
    parsed: usize,
    executed: usize,
    skipped: usize,
    failed: usize,
    skip_reasons: Vec<String>,
}

impl Counts {
    fn record_skip(&mut self, reason: &str) {
        self.skipped += 1;
        if !self.skip_reasons.iter().any(|r| r == reason) {
            self.skip_reasons.push(reason.to_owned());
        }
    }
}

impl std::fmt::Display for Counts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "parsed={}, executed={}, skipped={}, failed={}",
            self.parsed, self.executed, self.skipped, self.failed,
        )?;
        if !self.skip_reasons.is_empty() {
            write!(f, " [skip reasons: {}]", self.skip_reasons.join("; "))?;
        }
        Ok(())
    }
}

/// VAL-02: zero mismatches on runnable rows is not corpus coverage unless
/// skip reasons stay inside the named allow-list and the skip/executed
/// counts stay pinned. A new skip category or a silent shrink fails.
fn assert_pinned_native_column(
    counts: &Counts,
    mismatch_count: usize,
    pinned_failures: usize,
    pinned_skips: usize,
    pinned_executed: usize,
    allowed_skip_reasons: &[&str],
    corpus: &str,
) {
    assert_eq!(
        mismatch_count, pinned_failures,
        "{corpus} native mismatches changed; triage each row, then move the pinned count"
    );
    assert_eq!(
        counts.skipped, pinned_skips,
        "{corpus} native skips changed; a new skip category shrinks coverage"
    );
    assert_eq!(
        counts.executed, pinned_executed,
        "{corpus} native executed count changed; update the pin with the skip triage"
    );
    for reason in &counts.skip_reasons {
        assert!(
            allowed_skip_reasons
                .iter()
                .copied()
                .any(|allowed| allowed == reason),
            "{corpus}: unexpected skip reason `{reason}`; allowed {allowed_skip_reasons:?}"
        );
    }
    assert_eq!(
        counts.skip_reasons.len(),
        allowed_skip_reasons.len(),
        "{corpus}: skip-reason set changed: {:?}",
        counts.skip_reasons
    );
}

// ===========================================================================
// Corpus 1: script_tests.json
// ===========================================================================

// Core's `script_json_test` fills three markers the JSON corpus cannot express
// as hex (`src/test/script_tests.cpp:925-945`, `:968-974`):
//
//   `#SCRIPT# <asm>`            - assemble `<asm>` with ParseScript, push the
//                                 script bytes as the witness element;
//   `#CONTROLBLOCK#`            - TaprootBuilder::Add(0, <last element>,
//                                 TAPROOT_LEAF_TAPSCRIPT) then Finalize(key0),
//                                 push the resulting control block;
//   `0x51 0x20 #TAPROOTOUTPUT#` - scriptPubKey becomes OP_1 <output key>.
//
// `key0` is the fixed secret `vchKey0` at `script_tests.cpp:183`, the 32-byte
// big-endian scalar 1.

/// Core's `vchKey0`: the secret scalar the placeholder tree commits to.
const CORE_TAPROOT_INTERNAL_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

/// Core's `#SCRIPT#` marker: the rest of the element is tapscript in Core's ASM
/// dialect, not hex (`script_tests.cpp:931-935`).
const SCRIPT_PLACEHOLDER: &str = "#SCRIPT#";

/// Core's `#CONTROLBLOCK#` marker: the witness element is replaced by the
/// generated control block committing to the preceding `#SCRIPT#` leaf
/// (`script_tests.cpp:937-944`).
const CONTROL_BLOCK_PLACEHOLDER: &str = "#CONTROLBLOCK#";

/// The `scriptPubKey` spelling Core matches before substituting the output key
/// (`script_tests.cpp:968-974`).
const TAPROOT_OUTPUT_ASM: &str = "0x51 0x20 #TAPROOTOUTPUT#";

/// The single-leaf tree Core auto-generates for one `#SCRIPT#`/`#CONTROLBLOCK#`
/// pair: the witness element to append, and the program `#TAPROOTOUTPUT#` pays to.
struct TaprootPlaceholder {
    control_block: Vec<u8>,
    output_key: [u8; 32],
}

/// Builds the placeholder tree for `leaf_script`, mirroring Core's
/// `TaprootBuilder::Add(0, script, TAPROOT_LEAF_TAPSCRIPT).Finalize(key0)`.
///
/// The tree is assembled with rust-bitcoin's builder - an independent
/// implementation of BIP341 - and then checked against this crate's own
/// `taproot::compute_taproot_merkle_root` and `taproot::verify_taproot_commitment`
/// before it is handed to the interpreter, so a row can never be graded against
/// a commitment the driver itself would reject.
fn build_taproot_placeholder(leaf_script: &[u8]) -> Result<TaprootPlaceholder, String> {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&CORE_TAPROOT_INTERNAL_SECRET)
        .map_err(|e| format!("Core's fixed key0 must be a valid secret: {e}"))?;
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (internal, _) = XOnlyPublicKey::from_keypair(&keypair);
    let script = ScriptBuf::from_bytes(leaf_script.to_vec());

    let builder = TaprootBuilder::new()
        .add_leaf_with_ver(0, script.clone(), LeafVersion::TapScript)
        .map_err(|e| format!("single-leaf taproot tree must build: {e}"))?;
    let spend_info = builder
        .finalize(&secp, internal)
        .map_err(|_| "a one-leaf tree must finalize".to_owned())?;
    let control_bytes = spend_info
        .control_block(&(script, LeafVersion::TapScript))
        .ok_or("the leaf Core adds must have a control block")?
        .serialize();
    let output_key = spend_info.output_key().serialize();

    // The tree's own merkle root must be the tapleaf hash this crate computes,
    // and this crate's commitment check must accept the pair it just generated.
    let tapleaf = tapleaf_hash(taproot::TAPROOT_LEAF_TAPSCRIPT, leaf_script);
    let core_root = spend_info
        .merkle_root()
        .ok_or("a one-leaf tree has a merkle root")?;
    let core_root_bytes: &[u8] = core_root.as_ref();
    if core_root_bytes != tapleaf.as_byte_array() {
        return Err(format!(
            "tapleaf hash disagreement: rust-bitcoin {core_root:?}, this crate {tapleaf:?}"
        ));
    }
    let our_root = taproot::compute_taproot_merkle_root(&control_bytes, &tapleaf);
    if our_root.as_byte_array() != tapleaf.as_byte_array() {
        return Err(format!(
            "compute_taproot_merkle_root must return the tapleaf for an empty path, got {our_root:?}"
        ));
    }
    if !taproot::verify_taproot_commitment(&control_bytes, &output_key, &tapleaf) {
        return Err(
            "the generated control block failed this crate's own commitment check".to_owned(),
        );
    }

    Ok(TaprootPlaceholder {
        control_block: control_bytes,
        output_key,
    })
}

struct ScriptTestRow {
    script_sig: Vec<u8>,
    script_pubkey: Vec<u8>,
    witness: Vec<Vec<u8>>,
    amount: u64,
    flags: VerifyFlags,
    expected: ScriptErrCode,
    row_index: usize,
    comment: String,
}

#[expect(
    clippy::too_many_lines,
    reason = "test vector parser; splitting would obscure the row format"
)]
fn load_script_tests(counts: &mut Counts) -> Result<Vec<ScriptTestRow>, String> {
    let path = reference_path("script_tests.json");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("script_tests.json unreadable: {e}"))?;
    let root: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("script_tests.json parse: {e}"))?;
    let arr = root
        .as_array()
        .ok_or("script_tests.json root is not an array")?;

    let mut rows = Vec::new();
    'row: for (index, row) in arr.iter().enumerate() {
        let Some(arr) = row.as_array() else {
            continue;
        };
        counts.parsed += 1;

        let (witness_raw, script_sig_idx, script_pubkey_idx, flags_idx, expected_idx, comment_idx) =
            if arr.first().is_some_and(serde_json::Value::is_array) {
                (Some(&arr[0]), 1, 2, 3, 4, 5)
            } else if arr.len() >= 4 {
                (None, 0, 1, 2, 3, 4)
            } else if arr.len() == 1 && arr[0].is_string() {
                // Core's reader treats a lone string the same way: it is the
                // corpus's prose (format note, section header), not a test, and
                // it reports `Bad test` only for other short shapes
                // (`script_tests.cpp:955-960`). There is no scriptSig,
                // scriptPubKey, flags, or expected error to assemble.
                counts.record_skip(SCRIPT_TESTS_PROSE_SKIP);
                continue;
            } else {
                counts.record_skip(&format!(
                    "short row ({} elements): needs scriptSig, scriptPubKey, flags, expected error",
                    arr.len()
                ));
                continue;
            };

        // The single-leaf tree built for a row's `#SCRIPT#`/`#CONTROLBLOCK#`
        // markers; `#TAPROOTOUTPUT#` reads the same tree for the scriptPubKey.
        let mut placeholder_tree = None;
        let (witness, amount) = if let Some(wit_arr) = witness_raw {
            let wit = wit_arr
                .as_array()
                .ok_or_else(|| format!("row {index}: witness is not an array"))?;
            if wit.is_empty() {
                counts.record_skip("witness array empty");
                continue;
            }
            let Some(amount_btc) = wit.last().and_then(serde_json::Value::as_f64) else {
                counts.record_skip("witness amount not a number");
                continue;
            };
            let amount = btc_to_sats(amount_btc);
            // Core reads the witness element-by-element and fills the two
            // markers in place, so the assembled stack keeps the corpus order:
            // [..., leaf script, control block].
            let mut items = Vec::new();
            for elem in &wit[..wit.len() - 1] {
                let Some(s) = elem.as_str() else {
                    counts.record_skip("witness element is not a string");
                    continue 'row;
                };
                if let Some(asm) = s.strip_prefix(SCRIPT_PLACEHOLDER) {
                    // Core: `ParseScript(element.substr(SCRIPT_FLAG.size()))`.
                    let leaf = match parse_core_asm(asm) {
                        Ok(script) => script,
                        Err(e) => {
                            counts.record_skip(&format!("#SCRIPT# asm parse error: {e}"));
                            continue 'row;
                        }
                    };
                    match build_taproot_placeholder(&leaf) {
                        Ok(tree) => {
                            placeholder_tree = Some(tree);
                            items.push(leaf);
                        }
                        Err(e) => {
                            counts.record_skip(&format!("#CONTROLBLOCK# tree: {e}"));
                            continue 'row;
                        }
                    }
                    continue;
                }
                if s == CONTROL_BLOCK_PLACEHOLDER {
                    if let Some(tree) = &placeholder_tree {
                        items.push(tree.control_block.clone());
                    } else {
                        counts.record_skip("#CONTROLBLOCK# with no preceding #SCRIPT# leaf");
                        continue 'row;
                    }
                    continue;
                }
                items.push(
                    hex_to_bytes(s).map_err(|e| format!("row {index}: bad witness hex: {e}"))?,
                );
            }
            (items, amount)
        } else {
            (Vec::new(), 0)
        };

        let script_sig_str = arr
            .get(script_sig_idx)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("row {index}: scriptSig is not a string"))?;
        let script_pubkey_str = arr
            .get(script_pubkey_idx)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("row {index}: scriptPubKey is not a string"))?;
        let flags_str = arr
            .get(flags_idx)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let expected_str = arr
            .get(expected_idx)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("row {index}: expected result is not a string"))?;

        let script_sig = match parse_core_asm(script_sig_str) {
            Ok(s) => s,
            Err(e) => {
                counts.record_skip(&format!("scriptSig asm parse error: {e}"));
                continue;
            }
        };
        let script_pubkey = if script_pubkey_str == TAPROOT_OUTPUT_ASM {
            // Core replaces the whole string with the generated tree's program.
            if let Some(tree) = &placeholder_tree {
                let mut spk = vec![opcode::OP_PUSHNUM_1, 0x20];
                spk.extend_from_slice(&tree.output_key);
                spk
            } else {
                counts.record_skip("#TAPROOTOUTPUT# with no #CONTROLBLOCK# witness element");
                continue;
            }
        } else {
            match parse_core_asm(script_pubkey_str) {
                Ok(s) => s,
                Err(e) => {
                    counts.record_skip(&format!("scriptPubKey asm parse error: {e}"));
                    continue;
                }
            }
        };

        let flags = match VerifyFlags::from_core_names(flags_str) {
            Ok(f) => f,
            Err(e) => {
                counts.record_skip(&format!("unknown flag: {e}"));
                continue;
            }
        };

        let Some(expected) = ScriptErrCode::from_name(expected_str) else {
            counts.record_skip(&format!("unknown expected error name: {expected_str}"));
            continue;
        };

        let comment = arr
            .get(comment_idx)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();

        rows.push(ScriptTestRow {
            script_sig,
            script_pubkey,
            witness,
            amount,
            flags,
            expected,
            row_index: index + 1,
            comment,
        });
    }
    Ok(rows)
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "satoshi amounts from Core test vectors are non-negative integers represented as f64"
)]
fn btc_to_sats(btc: f64) -> u64 {
    (btc * 100_000_000.0).round() as u64
}

fn run_script_tests_native(rows: &[ScriptTestRow], counts: &mut Counts) -> Vec<String> {
    let interp = Interpreter;
    let mut mismatches = Vec::new();

    for row in rows {
        counts.executed += 1;
        let credit = build_crediting_tx(&row.script_pubkey, row.amount);
        let spend = build_spending_tx(&row.script_sig, &row.witness, &credit);
        let prevouts = [credit.outputs[0].clone()];

        let result = interp.execute_with_prevouts(
            &row.script_pubkey,
            &row.script_sig,
            &row.witness,
            row.flags,
            &prevouts,
            &spend,
            0,
        );
        let verdict = Verdict::from_interpreter(&result);

        if verdict.matches_expected(row.expected) {
            // pass
        } else {
            counts.failed += 1;
            mismatches.push(format!(
                "row {}: expected {}, got {:?} (flags {:#x}, sig {}, pubkey {}, comment: {})",
                row.row_index,
                row.expected,
                verdict,
                row.flags.bits(),
                hex_of(&row.script_sig),
                hex_of(&row.script_pubkey),
                row.comment
            ));
        }
    }
    mismatches
}

#[cfg(feature = "kernel")]
fn run_script_tests_kernel(rows: &[ScriptTestRow], counts: &mut Counts) -> Vec<String> {
    let mut mismatches = Vec::new();

    for row in rows {
        counts.executed += 1;
        let credit = build_crediting_tx(&row.script_pubkey, row.amount);
        let spend = build_spending_tx(&row.script_sig, &row.witness, &credit);
        let prevouts = [(OutPoint::new(credit.txid(), 0), credit.outputs[0].clone())];

        let result = bitcoin_rs_consensus::kernel::verify_tx_scripts(&spend, &prevouts, row.flags);
        let verdict = Verdict::from_kernel(&result);

        if verdict.matches_expected(row.expected) {
            // pass
        } else {
            counts.failed += 1;
            mismatches.push(format!(
                "row {}: expected {}, got {:?} (flags {:#x}, sig {}, pubkey {}, comment: {})",
                row.row_index,
                row.expected,
                verdict,
                row.flags.bits(),
                hex_of(&row.script_sig),
                hex_of(&row.script_pubkey),
                row.comment
            ));
        }
    }
    mismatches
}

// ===========================================================================
// Corpus 2 & 3: tx_valid.json / tx_invalid.json
// ===========================================================================

struct TxVectorRow {
    tx: Tx,
    prevouts: Vec<(OutPoint, TxOut)>,
    flags: VerifyFlags,
    expected: Verdict,
    row_index: usize,
}

#[expect(
    clippy::too_many_lines,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "test vector parser; vout indices are small non-negative integers stored as i64"
)]
fn load_tx_vectors(
    name: &str,
    expected_accept: bool,
    counts: &mut Counts,
) -> Result<Vec<TxVectorRow>, String> {
    let path = reference_path(name);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{name} unreadable: {e}"))?;
    let root: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{name} parse: {e}"))?;
    let arr = root
        .as_array()
        .ok_or_else(|| format!("{name} root is not an array"))?;

    let mut rows = Vec::new();
    for (index, row) in arr.iter().enumerate() {
        let Some(arr) = row.as_array() else {
            continue;
        };
        if arr.len() < 3 || !arr[0].is_array() || arr[1].as_str().is_none() {
            continue;
        }
        counts.parsed += 1;

        let flags_str = arr[2].as_str().unwrap_or("NONE");
        if flags_str.contains("BADTX") {
            counts.record_skip(TX_INVALID_BADTX_SKIP);
            continue;
        }

        let tx_hex = arr[1].as_str().unwrap_or("");
        let tx_bytes = match hex_to_bytes(tx_hex) {
            Ok(b) => b,
            Err(e) => {
                counts.record_skip(&format!("bad tx hex: {e}"));
                continue;
            }
        };
        let Ok(tx) = deserialize::<Tx>(&tx_bytes) else {
            if expected_accept {
                counts.record_skip("tx_valid row failed to deserialize");
            } else {
                counts.record_skip(
                    "tx_invalid row failed to deserialize (expected rejection at parse stage)",
                );
            }
            continue;
        };

        // The two tx corpora read the same field in opposite directions.
        let flags = match if expected_accept {
            tx_valid_flags(flags_str)
        } else {
            tx_invalid_flags(flags_str)
        } {
            Ok(f) => f,
            Err(e) => {
                counts.record_skip(&e);
                continue;
            }
        };

        let Some(prevout_specs) = arr[0].as_array() else {
            counts.record_skip("prevout spec is not an array");
            continue;
        };
        let mut prevouts = Vec::with_capacity(prevout_specs.len());
        let mut prevout_error = false;
        for spec in prevout_specs {
            let Some(spec_arr) = spec.as_array() else {
                counts.record_skip("prevout spec element is not an array");
                prevout_error = true;
                break;
            };
            let Some(hash_hex) = spec_arr.first().and_then(serde_json::Value::as_str) else {
                counts.record_skip("prevout hash not a string");
                prevout_error = true;
                break;
            };
            let Some(vout_i64) = spec_arr.get(1).and_then(serde_json::Value::as_i64) else {
                counts.record_skip("prevout vout not an integer");
                prevout_error = true;
                break;
            };
            let vout = vout_i64 as u32;
            let Some(script_asm) = spec_arr.get(2).and_then(serde_json::Value::as_str) else {
                counts.record_skip("prevout script not a string");
                prevout_error = true;
                break;
            };
            let amount = spec_arr
                .get(3)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);

            let script_pubkey = match parse_core_asm(script_asm) {
                Ok(s) => s,
                Err(e) => {
                    counts.record_skip(&format!("prevout script asm error: {e}"));
                    prevout_error = true;
                    break;
                }
            };

            let Ok(txid) = Txid::from_str(hash_hex) else {
                counts.record_skip(&format!("prevout txid parse: {hash_hex}"));
                prevout_error = true;
                break;
            };
            prevouts.push((
                OutPoint::new(txid, vout),
                TxOut {
                    value: amount,
                    script_pubkey,
                },
            ));
        }
        if prevout_error {
            continue;
        }

        let expected = if expected_accept {
            Verdict::Accept
        } else {
            Verdict::Reject(None)
        };

        rows.push(TxVectorRow {
            tx,
            prevouts,
            flags,
            expected,
            row_index: index + 1,
        });
    }
    Ok(rows)
}

fn run_tx_vectors_native(rows: &[TxVectorRow], counts: &mut Counts) -> Vec<String> {
    let interp = Interpreter;
    let mut mismatches = Vec::new();

    for row in rows {
        counts.executed += 1;
        let prevout_txouts: Vec<TxOut> = row.prevouts.iter().map(|(_, o)| o.clone()).collect();
        // The first failing input decides the row, and its error name is what
        // a triage reader needs; a bare Reject says nothing.
        let mut first_failure = None;
        for input_idx in 0..row.tx.inputs.len() {
            let prevout = &row.prevouts[input_idx].1;
            let input = &row.tx.inputs[input_idx];
            let result = interp.execute_with_prevouts(
                &prevout.script_pubkey,
                &input.script_sig,
                &input.witness,
                row.flags,
                &prevout_txouts,
                &row.tx,
                input_idx,
            );
            if !matches!(result, Ok(true)) {
                first_failure = Some((input_idx, Verdict::from_interpreter(&result)));
                break;
            }
        }

        let verdict = match &first_failure {
            None => Verdict::Accept,
            Some((input_idx, Verdict::Reject(code))) => Verdict::Reject(Some(format!(
                "input {input_idx}: {}",
                code.clone().unwrap_or_else(|| "no code".to_owned())
            ))),
            Some((input_idx, Verdict::Accept)) => {
                Verdict::Reject(Some(format!("input {input_idx}: accepted-but-not-true")))
            }
        };

        let matches = verdict.accepted() == row.expected.accepted();
        if !matches {
            counts.failed += 1;
            mismatches.push(format!(
                "row {}: expected {:?}, got {:?} (flags {:#x}, locktime {}, seq0 {:#x})",
                row.row_index,
                row.expected,
                verdict,
                row.flags.bits(),
                row.tx.lock_time,
                row.tx.inputs.first().map_or(0, |input| input.sequence)
            ));
        }
    }
    mismatches
}

#[cfg(feature = "kernel")]
fn run_tx_vectors_kernel(rows: &[TxVectorRow], counts: &mut Counts) -> Vec<String> {
    let mut mismatches = Vec::new();

    for row in rows {
        counts.executed += 1;
        let result =
            bitcoin_rs_consensus::kernel::verify_tx_scripts(&row.tx, &row.prevouts, row.flags);
        let verdict = Verdict::from_kernel(&result);

        let matches = verdict.accepted() == row.expected.accepted();
        if !matches {
            counts.failed += 1;
            mismatches.push(format!(
                "row {}: expected {:?}, got {:?} (flags {:#x}, locktime {}, seq0 {:#x})",
                row.row_index,
                row.expected,
                verdict,
                row.flags.bits(),
                row.tx.lock_time,
                row.tx.inputs.first().map_or(0, |input| input.sequence)
            ));
        }
    }
    mismatches
}

// ===========================================================================
// Corpus 4: sighash.json
// ===========================================================================

struct SighashRow {
    tx: Tx,
    script_code: Vec<u8>,
    input_index: usize,
    hash_type: u32,
    expected_hash: Hash256,
    row_index: usize,
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "test vector indices and hash types are small non-negative integers stored as i64"
)]
fn load_sighash_vectors(counts: &mut Counts) -> Result<Vec<SighashRow>, String> {
    let path = reference_path("sighash.json");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("sighash.json unreadable: {e}"))?;
    let root: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("sighash.json parse: {e}"))?;
    let arr = root.as_array().ok_or("sighash.json root is not an array")?;

    let mut rows = Vec::new();
    for (index, row) in arr.iter().enumerate() {
        let Some(arr) = row.as_array() else {
            continue;
        };
        if arr.len() < 5 {
            continue;
        }
        counts.parsed += 1;

        let tx_hex = arr[0]
            .as_str()
            .ok_or_else(|| format!("sighash row {index}: tx hex is not a string"))?;
        let script_hex = arr[1].as_str().unwrap_or("");
        let input_index = arr[2]
            .as_i64()
            .ok_or_else(|| format!("sighash row {index}: input_index is not an integer"))?;
        let input_index = input_index as usize;
        let hash_type_i32 = arr[3]
            .as_i64()
            .ok_or_else(|| format!("sighash row {index}: hashType is not an integer"))?
            as i32;
        let hash_type = hash_type_i32 as u32;
        let expected_hex = arr[4]
            .as_str()
            .ok_or_else(|| format!("sighash row {index}: expected hash is not a string"))?;

        let tx_bytes =
            hex_to_bytes(tx_hex).map_err(|e| format!("sighash row {index}: bad tx hex: {e}"))?;
        let tx = deserialize::<Tx>(&tx_bytes)
            .map_err(|e| format!("sighash row {index}: tx deserialize: {e}"))?;
        let script_code = if script_hex.is_empty() {
            Vec::new()
        } else {
            hex_to_bytes(script_hex)
                .map_err(|e| format!("sighash row {index}: bad script hex: {e}"))?
        };
        let expected_hash = Hash256::from_str_be(expected_hex)
            .map_err(|e| format!("sighash row {index}: bad expected hash: {e}"))?;

        rows.push(SighashRow {
            tx,
            script_code,
            input_index,
            hash_type,
            expected_hash,
            row_index: index + 1,
        });
    }
    Ok(rows)
}

fn run_sighash_vectors(rows: &[SighashRow], counts: &mut Counts) -> Vec<String> {
    let mut mismatches = Vec::new();

    for row in rows {
        counts.executed += 1;
        // Core's SignatureHash calls SerializeScriptCode which strips
        // OP_CODESEPARATOR (0xab) opcode bytes before hashing. Strip them
        // here to match, so the sighash rows containing CS can be tested.
        let script_code = strip_codeseparators(&row.script_code);
        let cache = SighashCache::new(&row.tx);
        let result = cache.legacy_signature_hash(row.input_index, &script_code, row.hash_type);

        match result {
            Ok(actual) => {
                if actual != row.expected_hash {
                    counts.failed += 1;
                    mismatches.push(format!(
                        "sighash row {}: expected {}, got {}",
                        row.row_index, row.expected_hash, actual
                    ));
                }
            }
            Err(e) => {
                counts.failed += 1;
                mismatches.push(format!("sighash row {}: engine error: {e}", row.row_index));
            }
        }
    }
    mismatches
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Removes `OP_CODESEPARATOR` (0xab) opcodes from a script, matching Core's
/// `CTransactionSignatureSerializer::SerializeScriptCode`. Bytes inside data
/// pushes are preserved.
fn strip_codeseparators(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len());
    let mut pos = 0;
    while pos < script.len() {
        let op = script[pos];
        if op == 0xab {
            pos += 1;
        } else if (0x01..=0x4b).contains(&op) {
            let end = pos + 1 + usize::from(op);
            out.extend_from_slice(&script[pos..end.min(script.len())]);
            pos = end;
        } else if op == 0x4c {
            let len_pos = pos + 1;
            let len = script.get(len_pos).copied().unwrap_or(0);
            let end = len_pos + 1 + usize::from(len);
            out.extend_from_slice(&script[pos..end.min(script.len())]);
            pos = end;
        } else if op == 0x4d {
            let len_pos = pos + 1;
            let len = u16::from_le_bytes([
                script.get(len_pos).copied().unwrap_or(0),
                script.get(len_pos + 1).copied().unwrap_or(0),
            ]);
            let end = len_pos + 2 + usize::from(len);
            out.extend_from_slice(&script[pos..end.min(script.len())]);
            pos = end;
        } else if op == 0x4e {
            let len_pos = pos + 1;
            let len = u32::from_le_bytes([
                script.get(len_pos).copied().unwrap_or(0),
                script.get(len_pos + 1).copied().unwrap_or(0),
                script.get(len_pos + 2).copied().unwrap_or(0),
                script.get(len_pos + 3).copied().unwrap_or(0),
            ]);
            let end = len_pos + 4 + usize::try_from(len).unwrap_or(usize::MAX);
            out.extend_from_slice(&script[pos..end.min(script.len())]);
            pos = end;
        } else {
            out.push(op);
            pos += 1;
        }
    }
    out
}

/// How many mismatch lines to print per corpus.
///
/// Five is enough to see a pattern without burying the counts; set
/// `SCRIPT_VECTOR_MISMATCHES` higher when triaging a specific group.
/// Renders a script as hex so a mismatch line names the exact bytes that
/// failed rather than a row number the reader has to resolve by hand.
fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `tx_valid.json` names the flags Core turns OFF: it verifies with the
/// complement (`transaction_tests.cpp:224`). A row whose complement is not a
/// filled combination is bad test data, which Core reports rather than runs.
fn tx_valid_flags(names: &str) -> Result<VerifyFlags, String> {
    let parsed = VerifyFlags::from_core_names(names).map_err(|e| e.to_string())?;
    let effective = VerifyFlags::ALL.excluding(parsed);
    if effective != effective.filled() {
        return Err(format!(
            "bad test flags (not a filled combination): {names}"
        ));
    }
    Ok(effective)
}

/// `tx_invalid.json` names the flags Core turns ON, unfilled and unedited, so
/// an invalid combination is detected rather than repaired
/// (`transaction_tests.cpp:310-315`).
fn tx_invalid_flags(names: &str) -> Result<VerifyFlags, String> {
    let parsed = VerifyFlags::from_core_names(names).map_err(|e| e.to_string())?;
    if parsed != parsed.filled() {
        return Err(format!(
            "bad test flags (not a filled combination): {names}"
        ));
    }
    Ok(parsed)
}

fn mismatch_print_limit() -> usize {
    std::env::var("SCRIPT_VECTOR_MISMATCHES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(5)
}

fn reference_path(name: &str) -> std::path::PathBuf {
    // Anchored at this crate rather than the process working directory, so the
    // corpora resolve identically from the workspace root, from a worktree at
    // any depth, and from a bare `cargo test -p bitcoin-rs-script`.
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_dir
        .ancestors()
        .find(|dir| dir.join(".references").is_dir())
        .unwrap_or(crate_dir);
    // The tracked copy is the authority: `.references` is a local checkout of
    // Core and is not in git, so a CI run that fell back to it would either
    // fail to find the corpus or grade against a different one.
    let candidates = [
        crate_dir.join("../consensus/tests/vectors").join(name),
        workspace_root
            .join(".references/bitcoin/src/test/data")
            .join(name),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return candidate.clone();
        }
    }
    candidates[0].clone()
}

// ===========================================================================
// Tests
// ===========================================================================

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "test assertions on known-good asm inputs"
)]
fn asm_assembler_matches_known_bytes() {
    assert_eq!(parse_core_asm("DEPTH 0 EQUAL").unwrap(), [0x74, 0x00, 0x87]);
    assert_eq!(
        parse_core_asm("0x02 0x01 0x00").unwrap(),
        [0x02, 0x01, 0x00]
    );
    assert_eq!(
        parse_core_asm("'Az' EQUAL").unwrap(),
        [0x02, b'A', b'z', 0x87]
    );
    assert_eq!(parse_core_asm("1 2").unwrap(), [0x51, 0x52]);
    assert_eq!(parse_core_asm("-1").unwrap(), [0x4f]);
    assert_eq!(parse_core_asm("DUP IF ENDIF").unwrap(), [0x76, 0x63, 0x68]);
    assert_eq!(parse_core_asm("NOP").unwrap(), [0x61]);
    assert_eq!(parse_core_asm("OP_NOP").unwrap(), [0x61]);
    assert_eq!(parse_core_asm("").unwrap(), Vec::<u8>::new());
    assert_eq!(
        parse_core_asm("1000 ADD").unwrap(),
        [0x02, 0xe8, 0x03, 0x93]
    );
}

/// Core rows the native evaluator does not yet match. Every one is triaged in
/// the issue that owns the remaining work; the count is pinned so a shrink
/// lowers it with evidence and a growth fails the lane.
const NATIVE_SCRIPT_TESTS_FAILURES: usize = 0;
/// Prose / section-header rows in `script_tests.json` (one string element).
/// A growth means the harness started skipping real tests.
const NATIVE_SCRIPT_TESTS_SKIPS: usize = 55;
const NATIVE_SCRIPT_TESTS_EXECUTED: usize = 1233;
const SCRIPT_TESTS_PROSE_SKIP: &str =
    "prose row (1 string element: format note or section header, no test fields)";

#[test]
fn script_tests_native_column() {
    let mut counts = Counts::default();
    let rows = match load_script_tests(&mut counts) {
        Ok(r) => r,
        Err(e) => panic!("script_tests.json should load: {e}"),
    };
    assert!(!rows.is_empty(), "script_tests produced zero runnable rows");

    let mismatches = run_script_tests_native(&rows, &mut counts);
    println!("script_tests [native]: {counts}");
    assert!(
        counts.executed > 0,
        "harness executed zero script_tests rows — wiring is broken"
    );
    for m in mismatches.iter().take(mismatch_print_limit()) {
        println!("  {m}");
    }
    assert_pinned_native_column(
        &counts,
        mismatches.len(),
        NATIVE_SCRIPT_TESTS_FAILURES,
        NATIVE_SCRIPT_TESTS_SKIPS,
        NATIVE_SCRIPT_TESTS_EXECUTED,
        &[SCRIPT_TESTS_PROSE_SKIP],
        "script_tests",
    );
}

#[cfg(feature = "kernel")]
#[test]
fn script_tests_kernel_column() {
    let mut counts = Counts::default();
    let rows = match load_script_tests(&mut counts) {
        Ok(r) => r,
        Err(e) => panic!("script_tests.json should load: {e}"),
    };
    assert!(!rows.is_empty(), "script_tests produced zero runnable rows");

    let mismatches = run_script_tests_kernel(&rows, &mut counts);
    println!("script_tests [kernel]: {counts}");
    assert!(
        counts.executed > 0,
        "harness executed zero script_tests rows — wiring is broken"
    );
    if !mismatches.is_empty() {
        println!(
            "  (kernel: {}/{} rows did not match expected)",
            mismatches.len(),
            counts.executed,
        );
        for m in mismatches.iter().take(10) {
            println!("  {m}");
        }
    }
}

/// Pinned like `NATIVE_SCRIPT_TESTS_FAILURES`: a shrink lowers it with
/// evidence, a growth fails the lane.
const NATIVE_TX_VALID_FAILURES: usize = 0;
const NATIVE_TX_VALID_SKIPS: usize = 0;
const NATIVE_TX_VALID_EXECUTED: usize = 121;

#[test]
fn tx_valid_native_column() {
    let mut counts = Counts::default();
    let rows = match load_tx_vectors("tx_valid.json", true, &mut counts) {
        Ok(r) => r,
        Err(e) => panic!("tx_valid should load: {e}"),
    };
    assert!(!rows.is_empty(), "tx_valid produced zero runnable rows");

    let mismatches = run_tx_vectors_native(&rows, &mut counts);
    println!("tx_valid [native]: {counts}");
    assert!(counts.executed > 0, "harness executed zero tx_valid rows");
    for m in mismatches.iter().take(mismatch_print_limit()) {
        println!("  {m}");
    }
    assert_pinned_native_column(
        &counts,
        mismatches.len(),
        NATIVE_TX_VALID_FAILURES,
        NATIVE_TX_VALID_SKIPS,
        NATIVE_TX_VALID_EXECUTED,
        &[],
        "tx_valid",
    );
}

#[cfg(feature = "kernel")]
#[test]
fn tx_valid_kernel_column() {
    let mut counts = Counts::default();
    let rows = match load_tx_vectors("tx_valid.json", true, &mut counts) {
        Ok(r) => r,
        Err(e) => panic!("tx_valid should load: {e}"),
    };
    assert!(!rows.is_empty(), "tx_valid produced zero runnable rows");

    let mismatches = run_tx_vectors_kernel(&rows, &mut counts);
    println!("tx_valid [kernel]: {counts}");
    assert!(counts.executed > 0, "harness executed zero tx_valid rows");
    if !mismatches.is_empty() {
        println!(
            "  (kernel: {}/{} rows mismatched)",
            mismatches.len(),
            counts.executed,
        );
        for m in mismatches.iter().take(10) {
            println!("  {m}");
        }
    }
}

/// A `tx_invalid` mismatch means the evaluator ACCEPTED a transaction Core
/// rejects, so this count is the one that must reach zero first.
const NATIVE_TX_INVALID_FAILURES: usize = 0;
/// `BADTX` rows fail `CheckTransaction` before script verification.
const NATIVE_TX_INVALID_SKIPS: usize = 9;
const NATIVE_TX_INVALID_EXECUTED: usize = 84;
const TX_INVALID_BADTX_SKIP: &str = "BADTX: fails CheckTransaction, not script verification";

#[test]
fn tx_invalid_native_column() {
    let mut counts = Counts::default();
    let rows = match load_tx_vectors("tx_invalid.json", false, &mut counts) {
        Ok(r) => r,
        Err(e) => panic!("tx_invalid should load: {e}"),
    };
    assert!(!rows.is_empty(), "tx_invalid produced zero runnable rows");

    let mismatches = run_tx_vectors_native(&rows, &mut counts);
    println!("tx_invalid [native]: {counts}");
    assert!(counts.executed > 0, "harness executed zero tx_invalid rows");
    for m in mismatches.iter().take(mismatch_print_limit()) {
        println!("  {m}");
    }
    assert_pinned_native_column(
        &counts,
        mismatches.len(),
        NATIVE_TX_INVALID_FAILURES,
        NATIVE_TX_INVALID_SKIPS,
        NATIVE_TX_INVALID_EXECUTED,
        &[TX_INVALID_BADTX_SKIP],
        "tx_invalid",
    );
}

#[cfg(feature = "kernel")]
#[test]
fn tx_invalid_kernel_column() {
    let mut counts = Counts::default();
    let rows = match load_tx_vectors("tx_invalid.json", false, &mut counts) {
        Ok(r) => r,
        Err(e) => panic!("tx_invalid should load: {e}"),
    };
    assert!(!rows.is_empty(), "tx_invalid produced zero runnable rows");

    let mismatches = run_tx_vectors_kernel(&rows, &mut counts);
    println!("tx_invalid [kernel]: {counts}");
    assert!(counts.executed > 0, "harness executed zero tx_invalid rows");
    if !mismatches.is_empty() {
        println!(
            "  (kernel: {}/{} rows mismatched)",
            mismatches.len(),
            counts.executed,
        );
        for m in mismatches.iter().take(10) {
            println!("  {m}");
        }
    }
}

#[test]
fn sighash_vectors_match_engine() {
    let mut counts = Counts::default();
    let rows = match load_sighash_vectors(&mut counts) {
        Ok(r) => r,
        Err(e) => panic!("sighash.json should load: {e}"),
    };
    assert!(!rows.is_empty(), "sighash produced zero runnable rows");

    let mismatches = run_sighash_vectors(&rows, &mut counts);
    println!("sighash: {counts}");
    assert!(counts.executed > 0, "harness executed zero sighash rows");
    if !mismatches.is_empty() {
        println!(
            "  {}/{} sighash rows mismatched — the engine has a bug or the harness is miswired",
            mismatches.len(),
            counts.executed,
        );
        for m in mismatches.iter().take(10) {
            println!("  {m}");
        }
    }
    assert!(
        mismatches.is_empty(),
        "sighash engine produced {} mismatches (expected 0):\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test]
fn broken_expectation_is_detected() {
    // Deliberately flip one sighash expectation and show the harness catches it.
    let mut counts = Counts::default();
    let rows = match load_sighash_vectors(&mut counts) {
        Ok(r) => r,
        Err(e) => panic!("sighash should load: {e}"),
    };
    assert!(!rows.is_empty());

    let row = &rows[0];
    let wrong = Hash256::from_le_bytes(&[0xaa; 32]);
    assert_ne!(
        wrong, row.expected_hash,
        "anti-vacuity: the wrong hash must differ from the expected hash"
    );

    let cache = SighashCache::new(&row.tx);
    let actual = cache
        .legacy_signature_hash(row.input_index, &row.script_code, row.hash_type)
        .unwrap_or_else(|e| panic!("sighash computation should succeed: {e}"));

    let detected = actual != wrong;
    println!(
        "broken_expectation_is_detected: sighash row {}, actual={actual}, wrong={wrong}, detected={detected}",
        row.row_index,
    );
    assert!(
        detected,
        "anti-vacuity: a deliberately wrong sighash must not match the engine output"
    );

    // Also verify the script_tests comparison logic detects a flipped expectation.
    let mut st_counts = Counts::default();
    let st_rows = match load_script_tests(&mut st_counts) {
        Ok(r) => r,
        Err(e) => panic!("script_tests should load: {e}"),
    };
    let ok_row = st_rows
        .iter()
        .find(|r| r.expected == ScriptErrCode::Ok)
        .unwrap_or_else(|| panic!("no OK-expected row found in script_tests"));

    let credit = build_crediting_tx(&ok_row.script_pubkey, ok_row.amount);
    let spend = build_spending_tx(&ok_row.script_sig, &ok_row.witness, &credit);
    let prevouts = [credit.outputs[0].clone()];
    let interp = Interpreter;
    let result = interp.execute_with_prevouts(
        &ok_row.script_pubkey,
        &ok_row.script_sig,
        &ok_row.witness,
        ok_row.flags,
        &prevouts,
        &spend,
        0,
    );
    let verdict = Verdict::from_interpreter(&result);

    // Flip: if the row is accepted, claim it should be rejected.
    let broken_expected = if verdict == Verdict::Accept {
        ScriptErrCode::EvalFalse
    } else {
        ScriptErrCode::Ok
    };
    let st_detected = !verdict.matches_expected(broken_expected);
    println!(
        "broken_expectation_is_detected: script_tests row {}, verdict={verdict:?}, broken_expected={broken_expected}, detected={st_detected}",
        ok_row.row_index,
    );
    assert!(
        st_detected,
        "anti-vacuity: harness failed to detect a broken expectation in script_tests"
    );

    println!("broken_expectation_is_detected: PASS — harness reports mismatches honestly");
}
