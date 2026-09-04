//! Script verification entry points over the native transaction type.
//!
//! The driver mirrors Core's `VerifyScript`/`VerifyWitnessProgram` flow: run
//! scriptSig then scriptPubKey through the opcode evaluator, apply P2SH
//! redeem-script evaluation, dispatch SegWit v0 spends through their witness
//! programs, and hand taproot key-path and script-path spends to the local
//! BIP341/BIP342 verifier.

use std::borrow::Cow;
use std::fmt;

use bitcoin_rs_primitives::{
    Amount, LockTime, Script, Sequence, Sighash, SighashCache, Tx, TxOut, Witness,
};
use secp256k1::{Message, XOnlyPublicKey, schnorr::Signature};
use thiserror::Error;

use crate::checker::{SigVersion, TxSignatureChecker};
use crate::eval::{self, MAX_SCRIPT_ELEMENT_SIZE};
use crate::script::{is_p2tr, is_push_only, witness_program};
use crate::stack::{ScriptItem, Stack};
use crate::taproot;

/// Verification flags passed to the delegated consensus script engine.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct VerifyFlags(u32);

impl VerifyFlags {
    /// No verification flags.
    pub const NONE: Self = Self(0);
    /// Evaluate P2SH subscripts (BIP16).
    pub const P2SH: Self = Self(1 << 0);
    /// Require strict signature and public-key encodings.
    pub const STRICTENC: Self = Self(1 << 1);
    /// Require strict DER signatures (BIP66).
    pub const DERSIG: Self = Self(1 << 2);
    /// Require low-S ECDSA signatures.
    pub const LOW_S: Self = Self(1 << 3);
    /// Require empty CHECKMULTISIG dummy element (BIP147).
    pub const NULLDUMMY: Self = Self(1 << 4);
    /// Require scriptSig push-only form.
    pub const SIGPUSHONLY: Self = Self(1 << 5);
    /// Require minimal push and numeric encodings.
    pub const MINIMALDATA: Self = Self(1 << 6);
    /// Discourage NOPs reserved for future soft forks.
    pub const DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 7);
    /// Require a single true stack item after evaluation.
    pub const CLEANSTACK: Self = Self(1 << 8);
    /// Enable `OP_CHECKLOCKTIMEVERIFY` (BIP65).
    pub const CHECKLOCKTIMEVERIFY: Self = Self(1 << 9);
    /// Enable `OP_CHECKSEQUENCEVERIFY` (BIP112).
    pub const CHECKSEQUENCEVERIFY: Self = Self(1 << 10);
    /// Enable segregated witness validation (BIP141/BIP143).
    pub const WITNESS: Self = Self(1 << 11);
    /// Discourage unknown witness program versions.
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Self = Self(1 << 12);
    /// Require minimal IF/NOTIF arguments in segwit scripts.
    pub const MINIMALIF: Self = Self(1 << 13);
    /// Require failed signature checks to consume empty signatures.
    pub const NULLFAIL: Self = Self(1 << 14);
    /// Require compressed public keys in segwit scripts.
    pub const WITNESS_PUBKEYTYPE: Self = Self(1 << 15);
    /// Make `CODESEPARATOR` and `FindAndDelete` fail non-segwit scripts.
    pub const CONST_SCRIPTCODE: Self = Self(1 << 16);
    /// Enable taproot and tapscript validation (BIP341/BIP342).
    pub const TAPROOT: Self = Self(1 << 17);
    /// Discourage unknown taproot leaf versions.
    pub const DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: Self = Self(1 << 18);
    /// Discourage unknown `OP_SUCCESS` opcodes.
    pub const DISCOURAGE_OP_SUCCESS: Self = Self(1 << 19);
    /// Discourage unknown public-key versions in tapscript.
    pub const DISCOURAGE_UPGRADABLE_PUBKEYTYPE: Self = Self(1 << 20);
    /// Mandatory consensus flags used for block validation after taproot activation.
    pub const MANDATORY: Self = Self(
        Self::P2SH.0
            | Self::DERSIG.0
            | Self::NULLDUMMY.0
            | Self::CHECKLOCKTIMEVERIFY.0
            | Self::CHECKSEQUENCEVERIFY.0
            | Self::WITNESS.0
            | Self::TAPROOT.0,
    );
    /// Standard relay flags; useful for vector tests that request policy checks.
    pub const STANDARD: Self = Self(
        Self::MANDATORY.0
            | Self::STRICTENC.0
            | Self::LOW_S.0
            | Self::MINIMALDATA.0
            | Self::DISCOURAGE_UPGRADABLE_NOPS.0
            | Self::CLEANSTACK.0
            | Self::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.0
            | Self::MINIMALIF.0
            | Self::NULLFAIL.0
            | Self::WITNESS_PUBKEYTYPE.0
            | Self::CONST_SCRIPTCODE.0
            | Self::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION.0
            | Self::DISCOURAGE_OP_SUCCESS.0
            | Self::DISCOURAGE_UPGRADABLE_PUBKEYTYPE.0,
    );

    /// Builds flags from raw Core-compatible bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns raw Core-compatible flag bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns the full consensus-authority bit set, including taproot for bitcoinkernel.
    #[must_use]
    pub const fn kernel_bits(self) -> u32 {
        self.0 & Self::MANDATORY.0
    }

    /// Every flag bit this crate defines, the mask Core calls
    /// `MAX_SCRIPT_VERIFY_FLAGS` minus the bits it has not assigned.
    pub const ALL: Self =
        Self(Self::STANDARD.0 | Self::SIGPUSHONLY.0 | Self::CONST_SCRIPTCODE.0 | Self::MINIMALIF.0);

    /// Returns the bits of `self` that `other` does not set.
    #[must_use]
    pub const fn excluding(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Applies Core's flag implications: `CLEANSTACK` implies `WITNESS`, and
    /// `WITNESS` implies `P2SH`.
    ///
    /// Core asserts these combinations in `VerifyScript` because relaxing them
    /// would turn a soft fork into a hard one - a chain could go from
    /// `CLEANSTACK` alone to `P2SH + CLEANSTACK` and change what validates.
    /// A library cannot assert on its caller, so the driver normalizes instead,
    /// which is what Core's own vector harness does through `FillFlags`.
    #[must_use]
    pub const fn filled(self) -> Self {
        let mut bits = self.0;
        if bits & Self::CLEANSTACK.0 != 0 {
            bits |= Self::WITNESS.0;
        }
        if bits & Self::WITNESS.0 != 0 {
            bits |= Self::P2SH.0;
        }
        Self(bits)
    }

    /// Returns true when all `other` bits are present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Adds another flag set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Parses a comma-separated Core test-vector flag string.
    pub fn from_core_names(names: &str) -> Result<Self, ScriptError> {
        let mut flags = Self::NONE;
        for name in names
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            flags = flags.union(match name {
                "NONE" => Self::NONE,
                "P2SH" => Self::P2SH,
                "STRICTENC" => Self::STRICTENC,
                "DERSIG" => Self::DERSIG,
                "LOW_S" => Self::LOW_S,
                "NULLDUMMY" => Self::NULLDUMMY,
                "SIGPUSHONLY" => Self::SIGPUSHONLY,
                "MINIMALDATA" => Self::MINIMALDATA,
                "DISCOURAGE_UPGRADABLE_NOPS" => Self::DISCOURAGE_UPGRADABLE_NOPS,
                "CLEANSTACK" => Self::CLEANSTACK,
                "CHECKLOCKTIMEVERIFY" => Self::CHECKLOCKTIMEVERIFY,
                "CHECKSEQUENCEVERIFY" => Self::CHECKSEQUENCEVERIFY,
                "WITNESS" => Self::WITNESS,
                "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                    Self::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
                }
                "MINIMALIF" => Self::MINIMALIF,
                "NULLFAIL" => Self::NULLFAIL,
                "WITNESS_PUBKEYTYPE" => Self::WITNESS_PUBKEYTYPE,
                "CONST_SCRIPTCODE" => Self::CONST_SCRIPTCODE,
                "TAPROOT" => Self::TAPROOT,
                "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => {
                    Self::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
                }
                "DISCOURAGE_OP_SUCCESS" => Self::DISCOURAGE_OP_SUCCESS,
                "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => Self::DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
                unknown => {
                    return Err(ScriptError::UnknownFlag {
                        name: unknown.to_owned(),
                    });
                }
            });
        }
        Ok(flags)
    }
}

impl From<VerifyFlags> for u32 {
    fn from(flags: VerifyFlags) -> Self {
        flags.bits()
    }
}

/// Core-named script error codes, one variant per case in `ScriptErrorString`.
///
/// The [`fmt::Display`] impl renders the exact Core case name (without the
/// `SCRIPT_ERR_` prefix) so error messages match Bitcoin Core's
/// `script_error.cpp` output.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ScriptErrCode {
    /// `SCRIPT_ERR_EVAL_FALSE`
    EvalFalse,
    /// `SCRIPT_ERR_VERIFY`
    Verify,
    /// `SCRIPT_ERR_EQUALVERIFY`
    EqualVerify,
    /// `SCRIPT_ERR_CHECKMULTISIGVERIFY`
    CheckMultisigVerify,
    /// `SCRIPT_ERR_CHECKSIGVERIFY`
    CheckSigVerify,
    /// `SCRIPT_ERR_NUMEQUALVERIFY`
    NumEqualVerify,
    /// `SCRIPT_ERR_SCRIPT_SIZE`
    ScriptSize,
    /// `SCRIPT_ERR_PUSH_SIZE`
    PushSize,
    /// `SCRIPT_ERR_OP_COUNT`
    OpCount,
    /// `SCRIPT_ERR_STACK_SIZE`
    StackSize,
    /// `SCRIPT_ERR_SIG_COUNT`
    SigCount,
    /// `SCRIPT_ERR_PUBKEY_COUNT`
    PubkeyCount,
    /// `SCRIPT_ERR_BAD_OPCODE`
    BadOpcode,
    /// `SCRIPT_ERR_DISABLED_OPCODE`
    DisabledOpcode,
    /// `SCRIPT_ERR_INVALID_STACK_OPERATION`
    InvalidStackOperation,
    /// `SCRIPT_ERR_INVALID_ALTSTACK_OPERATION`
    InvalidAltstackOperation,
    /// `SCRIPT_ERR_OP_RETURN`
    OpReturn,
    /// `SCRIPT_ERR_UNBALANCED_CONDITIONAL`
    UnbalancedConditional,
    /// `SCRIPT_ERR_NEGATIVE_LOCKTIME`
    NegativeLocktime,
    /// `SCRIPT_ERR_UNSATISFIED_LOCKTIME`
    UnsatisfiedLocktime,
    /// `SCRIPT_ERR_SIG_HASHTYPE`
    SigHashtype,
    /// `SCRIPT_ERR_SIG_DER`
    SigDer,
    /// `SCRIPT_ERR_MINIMALDATA`
    MinimalData,
    /// `SCRIPT_ERR_SIG_PUSHONLY`
    SigPushonly,
    /// `SCRIPT_ERR_SIG_HIGH_S`
    SigHighS,
    /// `SCRIPT_ERR_SIG_NULLDUMMY`
    SigNullDummy,
    /// `SCRIPT_ERR_MINIMALIF`
    MinimalIf,
    /// `SCRIPT_ERR_SIG_NULLFAIL`
    SigNullFail,
    /// `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS`
    DiscourageUpgradableNops,
    /// `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`
    DiscourageUpgradableWitnessProgram,
    /// `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`
    DiscourageUpgradableTaprootVersion,
    /// `SCRIPT_ERR_DISCOURAGE_OP_SUCCESS`
    DiscourageOpSuccess,
    /// `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE`
    DiscourageUpgradablePubkeyType,
    /// `SCRIPT_ERR_PUBKEYTYPE`
    PubkeyType,
    /// `SCRIPT_ERR_CLEANSTACK`
    CleanStack,
    /// `SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH`
    WitnessProgramWrongLength,
    /// `SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY`
    WitnessProgramWitnessEmpty,
    /// `SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH`
    WitnessProgramMismatch,
    /// `SCRIPT_ERR_WITNESS_MALLEATED`
    WitnessMalleated,
    /// `SCRIPT_ERR_WITNESS_MALLEATED_P2SH`
    WitnessMalleatedP2sh,
    /// `SCRIPT_ERR_WITNESS_UNEXPECTED`
    WitnessUnexpected,
    /// `SCRIPT_ERR_WITNESS_PUBKEYTYPE`
    WitnessPubkeyType,
    /// `SCRIPT_ERR_SCHNORR_SIG_SIZE`
    SchnorrSigSize,
    /// `SCRIPT_ERR_SCHNORR_SIG_HASHTYPE`
    SchnorrSigHashtype,
    /// `SCRIPT_ERR_SCHNORR_SIG`
    SchnorrSig,
    /// `SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE`
    TaprootWrongControlSize,
    /// `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT`
    TapscriptValidationWeight,
    /// `SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG`
    TapscriptCheckMultiSig,
    /// `SCRIPT_ERR_TAPSCRIPT_MINIMALIF`
    TapscriptMinimalIf,
    /// `SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY`
    TapscriptEmptyPubkey,
    /// `SCRIPT_ERR_OP_CODESEPARATOR`
    OpCodeSeparator,
    /// `SCRIPT_ERR_SIG_FINDANDDELETE`
    SigFindAndDelete,
    /// `SCRIPT_ERR_SCRIPTNUM`
    ScriptNum,
}

impl fmt::Display for ScriptErrCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::EvalFalse => "EVAL_FALSE",
            Self::Verify => "VERIFY",
            Self::EqualVerify => "EQUALVERIFY",
            Self::CheckMultisigVerify => "CHECKMULTISIGVERIFY",
            Self::CheckSigVerify => "CHECKSIGVERIFY",
            Self::NumEqualVerify => "NUMEQUALVERIFY",
            Self::ScriptSize => "SCRIPT_SIZE",
            Self::PushSize => "PUSH_SIZE",
            Self::OpCount => "OP_COUNT",
            Self::StackSize => "STACK_SIZE",
            Self::SigCount => "SIG_COUNT",
            Self::PubkeyCount => "PUBKEY_COUNT",
            Self::BadOpcode => "BAD_OPCODE",
            Self::DisabledOpcode => "DISABLED_OPCODE",
            Self::InvalidStackOperation => "INVALID_STACK_OPERATION",
            Self::InvalidAltstackOperation => "INVALID_ALTSTACK_OPERATION",
            Self::OpReturn => "OP_RETURN",
            Self::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            Self::NegativeLocktime => "NEGATIVE_LOCKTIME",
            Self::UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
            Self::SigHashtype => "SIG_HASHTYPE",
            Self::SigDer => "SIG_DER",
            Self::MinimalData => "MINIMALDATA",
            Self::SigPushonly => "SIG_PUSHONLY",
            Self::SigHighS => "SIG_HIGH_S",
            Self::SigNullDummy => "SIG_NULLDUMMY",
            Self::MinimalIf => "MINIMALIF",
            Self::SigNullFail => "SIG_NULLFAIL",
            Self::DiscourageUpgradableNops => "DISCOURAGE_UPGRADABLE_NOPS",
            Self::DiscourageUpgradableWitnessProgram => "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            Self::DiscourageUpgradableTaprootVersion => "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
            Self::DiscourageOpSuccess => "DISCOURAGE_OP_SUCCESS",
            Self::DiscourageUpgradablePubkeyType => "DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
            Self::PubkeyType => "PUBKEYTYPE",
            Self::CleanStack => "CLEANSTACK",
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
            Self::TapscriptCheckMultiSig => "TAPSCRIPT_CHECKMULTISIG",
            Self::TapscriptMinimalIf => "TAPSCRIPT_MINIMALIF",
            Self::TapscriptEmptyPubkey => "TAPSCRIPT_EMPTY_PUBKEY",
            Self::OpCodeSeparator => "OP_CODESEPARATOR",
            Self::SigFindAndDelete => "SIG_FINDANDDELETE",
            Self::ScriptNum => "SCRIPTNUM",
        };
        f.write_str(name)
    }
}

/// Script execution errors surfaced by the script crate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScriptError {
    /// The requested input index was not present in the transaction.
    #[error("input index {index} out of range for {inputs} inputs")]
    InputIndexOutOfRange {
        /// Requested input index.
        index: usize,
        /// Transaction input count.
        inputs: usize,
    },
    /// A Core vector flag name was not known by this crate.
    #[error("unknown script verify flag {name}")]
    UnknownFlag {
        /// Unknown flag name.
        name: String,
    },
    /// The transaction could not be serialized for the delegated verifier.
    #[error("transaction serialization failed: {0}")]
    Serialization(String),
    /// The delegated consensus verifier rejected the script.
    #[error("script verification failed: {0}")]
    Verification(String),
    /// Taproot key-path verification requires all prevouts for multi-input transactions.
    #[error("taproot key-path verification requires all prevouts for multi-input transactions")]
    TaprootPrevoutsUnavailable,
    /// The script evaluated to a Core-named failure.
    #[error("script failed: {code}")]
    Invalid {
        /// Core's script error name for this failure.
        code: ScriptErrCode,
    },
}

/// Public script verifier for the portable posture.
///
/// Executes legacy, `P2SH`, and segwit v0 spends through the native opcode
/// evaluator, and taproot key-path and script-path spends via the local
/// BIP341/BIP342 verifier.
#[derive(Debug, Default, Clone, Copy)]
pub struct Interpreter;

impl Interpreter {
    /// Number of taproot inputs at which block validation uses the batch Schnorr path.
    pub const BATCH_SCHNORR_THRESHOLD: usize = 16;

    /// Executes a script spend through the enabled script backend.
    ///
    /// When `script_sig` and `witness` already match the bytes stored on
    /// `tx.inputs[input_idx]` — true for every block/mempool validation caller,
    /// which reads them straight off the transaction — `tx` is used as-is with
    /// no clone. Only callers that pass substitute bytes (e.g. vector tests
    /// grafting a foreign witness) pay for a clone to splice them in.
    ///
    /// Taproot key-path verification needs every spent output. Callers that only
    /// have the current input's prevout should prefer
    /// [`Self::execute_with_prevouts`] when the full ordered set is available;
    /// this wrapper forwards a one-element slice and therefore still rejects
    /// multi-input taproot key-path spends with
    /// [`ScriptError::TaprootPrevoutsUnavailable`].
    pub fn execute(
        &self,
        script_pubkey: &[u8],
        script_sig: &[u8],
        witness: &[Vec<u8>],
        flags: VerifyFlags,
        prevout: &TxOut,
        tx: &Tx,
        input_idx: usize,
    ) -> Result<bool, ScriptError> {
        self.execute_with_prevouts(
            script_pubkey,
            script_sig,
            witness,
            flags,
            std::slice::from_ref(prevout),
            tx,
            input_idx,
        )
    }

    /// Executes a script spend with the complete ordered prevout set.
    ///
    /// `prevouts` must be aligned with `tx.inputs` (same length, input order).
    /// BIP341 key-path sighashes commit to every spent output, so multi-input
    /// taproot spends require the full slice.
    pub fn execute_with_prevouts(
        &self,
        script_pubkey: &[u8],
        script_sig: &[u8],
        witness: &[Vec<u8>],
        flags: VerifyFlags,
        prevouts: &[TxOut],
        tx: &Tx,
        input_idx: usize,
    ) -> Result<bool, ScriptError> {
        let inputs = tx.inputs.len();
        let input = tx
            .inputs
            .get(input_idx)
            .ok_or(ScriptError::InputIndexOutOfRange {
                index: input_idx,
                inputs,
            })?;
        // `execute` forwards a one-element slice for the current input. Full-set
        // callers pass `prevouts.len() == tx.inputs.len()` in input order.
        let prevout = if prevouts.len() == inputs {
            prevouts
                .get(input_idx)
                .ok_or(ScriptError::TaprootPrevoutsUnavailable)?
        } else if prevouts.len() == 1 {
            prevouts
                .first()
                .ok_or(ScriptError::TaprootPrevoutsUnavailable)?
        } else {
            return Err(ScriptError::TaprootPrevoutsUnavailable);
        };

        let matches_tx = input.script_sig.as_slice() == script_sig
            && input.witness.len() == witness.len()
            && input
                .witness
                .iter()
                .zip(witness.iter())
                .all(|(stored, provided)| stored == provided);
        let spending: Cow<'_, Tx> = if matches_tx {
            Cow::Borrowed(tx)
        } else {
            let mut grafted = tx.clone();
            let grafted_input =
                grafted
                    .inputs
                    .get_mut(input_idx)
                    .ok_or(ScriptError::InputIndexOutOfRange {
                        index: input_idx,
                        inputs,
                    })?;
            grafted_input.script_sig = Script::from_bytes(script_sig.to_vec());
            grafted_input.witness = Witness::from_stack(witness.to_vec());
            Cow::Owned(grafted)
        };

        if is_p2tr(script_pubkey) && flags.contains(VerifyFlags::TAPROOT) {
            return verify_taproot(
                &spending,
                input_idx,
                script_pubkey,
                witness,
                prevouts,
                flags,
            );
        }

        let mut checker = TxSignatureChecker::new(&spending, input_idx, prevout.value, prevouts);
        verify_script(
            script_sig,
            script_pubkey,
            witness,
            flags.filled(),
            &mut checker,
        )?;
        Ok(true)
    }
}

fn invalid(code: ScriptErrCode) -> ScriptError {
    ScriptError::Invalid { code }
}

/// Mirrors Core's `VerifyScript`: scriptSig, then scriptPubKey, then the P2SH
/// and witness redirections the flags admit, then `CLEANSTACK`.
fn verify_script(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    flags: VerifyFlags,
    checker: &mut TxSignatureChecker<'_>,
) -> Result<(), ScriptError> {
    if flags.contains(VerifyFlags::SIGPUSHONLY) && !is_push_only(script_sig) {
        return Err(invalid(ScriptErrCode::SigPushonly));
    }
    // Witness data is only ever legitimate for a program this function
    // reaches below; anything left unconsumed is malleation.
    let mut witness_used = false;

    let mut stack = Stack::new();
    let mut weight: Option<i64> = None;
    eval::eval_script(
        &mut stack,
        script_sig,
        flags,
        checker,
        SigVersion::Base,
        &mut weight,
        None,
    )?;
    // P2SH needs the scriptSig's own result, because scriptPubKey execution
    // consumes the redeem script off the top.
    let redeem_stack = stack.clone();
    eval::eval_script(
        &mut stack,
        script_pubkey,
        flags,
        checker,
        SigVersion::Base,
        &mut weight,
        None,
    )?;
    require_true_top(&stack)?;

    if flags.contains(VerifyFlags::WITNESS) {
        if let Some((version, program)) = witness_program(script_pubkey) {
            if !script_sig.is_empty() {
                return Err(invalid(ScriptErrCode::WitnessMalleated));
            }
            verify_witness_program(witness, version, program, flags, checker, &mut stack)?;
            witness_used = true;
        }
    }

    let is_p2sh = flags.contains(VerifyFlags::P2SH) && crate::script::is_p2sh(script_pubkey);
    if is_p2sh {
        if !is_push_only(script_sig) {
            return Err(invalid(ScriptErrCode::SigPushonly));
        }
        stack = redeem_stack;
        let redeem = match stack.pop() {
            Ok(item) => item_bytes_owned(&item),
            Err(_) => return Err(invalid(ScriptErrCode::InvalidStackOperation)),
        };
        eval::eval_script(
            &mut stack,
            &redeem,
            flags,
            checker,
            SigVersion::Base,
            &mut weight,
            None,
        )?;
        require_true_top(&stack)?;

        if flags.contains(VerifyFlags::WITNESS) {
            if let Some((version, program)) = witness_program(&redeem) {
                // The scriptSig may push exactly the redeem script and nothing
                // else; any other shape lets a third party rewrite it.
                if script_sig != crate::script::push_data(&redeem).as_slice() {
                    return Err(invalid(ScriptErrCode::WitnessMalleatedP2sh));
                }
                verify_witness_program(witness, version, program, flags, checker, &mut stack)?;
                witness_used = true;
            }
        }
    }

    if flags.contains(VerifyFlags::WITNESS) && !witness_used && !witness.is_empty() {
        return Err(invalid(ScriptErrCode::WitnessUnexpected));
    }

    // Core's CLEANSTACK assertion is meaningful only when P2SH or WITNESS
    // activates the corresponding stack-discipline path. Policy vectors may
    // request CLEANSTACK alone; those legacy spends retain the normal
    // final-top-item check.
    if flags.contains(VerifyFlags::CLEANSTACK)
        && (flags.contains(VerifyFlags::P2SH) || flags.contains(VerifyFlags::WITNESS))
    {
        if stack.len() != 1 {
            return Err(invalid(ScriptErrCode::CleanStack));
        }
    }

    Ok(())
}

/// Mirrors Core's `VerifyWitnessProgram` for the versions this driver serves.
fn verify_witness_program(
    witness: &[Vec<u8>],
    version: u8,
    program: &[u8],
    flags: VerifyFlags,
    checker: &mut TxSignatureChecker<'_>,
    stack: &mut Stack,
) -> Result<(), ScriptError> {
    if version != 0 {
        // Taproot arrives here only without the TAPROOT flag, and unknown
        // versions stay spendable by consensus so future soft forks can define
        // them; policy discourages relaying them.
        if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
            return Err(invalid(ScriptErrCode::DiscourageUpgradableWitnessProgram));
        }
        stack.clear();
        stack
            .push(ScriptItem::Num(1))
            .map_err(|_| invalid(ScriptErrCode::StackSize))?;
        return Ok(());
    }

    let mut witness_stack = Stack::new();
    let (witness_script, elements) = match program.len() {
        32 => {
            let Some((script, rest)) = witness.split_last() else {
                return Err(invalid(ScriptErrCode::WitnessProgramWitnessEmpty));
            };
            if sha256_of(script) != program {
                return Err(invalid(ScriptErrCode::WitnessProgramMismatch));
            }
            (script.clone(), rest)
        }
        20 => {
            if witness.len() != 2 {
                return Err(invalid(ScriptErrCode::WitnessProgramMismatch));
            }
            (p2wpkh_script_code(program), witness)
        }
        _ => return Err(invalid(ScriptErrCode::WitnessProgramWrongLength)),
    };

    for element in elements {
        if element.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(invalid(ScriptErrCode::PushSize));
        }
        witness_stack
            .push(ScriptItem::Bytes(element.as_slice().into()))
            .map_err(|_| invalid(ScriptErrCode::StackSize))?;
    }

    let mut weight: Option<i64> = None;
    eval::eval_script(
        &mut witness_stack,
        &witness_script,
        flags,
        checker,
        SigVersion::WitnessV0,
        &mut weight,
        None,
    )?;

    // Witness execution is its own stack discipline: exactly one true item,
    // regardless of whether CLEANSTACK is set.
    if witness_stack.len() != 1 {
        return Err(invalid(ScriptErrCode::CleanStack));
    }
    require_true_top(&witness_stack)?;
    *stack = witness_stack;
    Ok(())
}

/// The implicit P2WPKH witness script: `DUP HASH160 <program> EQUALVERIFY CHECKSIG`.
fn p2wpkh_script_code(program: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(5 + program.len());
    script.push(0x76);
    script.push(0xa9);
    script.push(0x14);
    script.extend_from_slice(program);
    script.push(0x88);
    script.push(0xac);
    script
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn item_bytes_owned(item: &ScriptItem) -> Vec<u8> {
    match item {
        ScriptItem::Num(value) => crate::script::push_int(*value),
        ScriptItem::Bytes(bytes) => bytes.to_vec(),
    }
}

fn require_true_top(stack: &Stack) -> Result<(), ScriptError> {
    let top = stack
        .peek()
        .map_err(|_| invalid(ScriptErrCode::EvalFalse))?;
    if eval::item_is_true(top) {
        Ok(())
    } else {
        Err(invalid(ScriptErrCode::EvalFalse))
    }
}

/// Unified taproot verification: key-path and script-path (BIP341/BIP342).
///
/// Mirrors Core's `VerifyWitnessProgram` taproot branch. Strips an optional
/// annex, dispatches to key-path (single remaining element) or script-path
/// (control block + leaf script), and executes tapscript through the native
/// evaluator with `SigVersion::Tapscript`.
fn verify_taproot(
    spending: &Tx,
    input_idx: usize,
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    prevouts: &[TxOut],
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    if prevouts.len() != spending.inputs.len() {
        return Err(ScriptError::TaprootPrevoutsUnavailable);
    }

    // The 32-byte output key is the witness program (bytes 2..34 of the
    // scriptPubKey). `is_p2tr` already confirmed the shape.
    let program = script_pubkey
        .get(2..34)
        .ok_or_else(|| ScriptError::Verification("taproot program is not 32 bytes".to_owned()))?;

    if witness.is_empty() {
        return Err(invalid(ScriptErrCode::WitnessProgramWitnessEmpty));
    }

    // Work on an owned copy so we can pop the annex / control / script.
    let mut stack: Vec<Vec<u8>> = witness.to_vec();

    // Strip annex: if the last element is non-empty and starts with 0x50.
    // Core: "if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG)"
    let annex_bytes = strip_annex(&mut stack);

    if stack.len() == 1 {
        verify_taproot_keypath(
            spending,
            input_idx,
            program,
            &stack,
            annex_bytes.as_deref(),
            prevouts,
        )
    } else {
        verify_taproot_scriptpath(
            spending,
            input_idx,
            program,
            witness,
            &mut stack,
            annex_bytes,
            prevouts,
            flags,
        )
    }
}

/// Strips the annex from the witness stack when present (BIP341).
///
/// Mirrors Core's annex-stripping condition: when the stack has at least two
/// elements and the last is non-empty with a leading `ANNEX_TAG` byte.
fn strip_annex(stack: &mut Vec<Vec<u8>>) -> Option<Vec<u8>> {
    if stack.len() < 2 {
        return None;
    }
    let is_annex = stack
        .last()
        .is_some_and(|last| !last.is_empty() && last[0] == taproot::ANNEX_TAG);
    if is_annex { stack.pop() } else { None }
}

/// Verifies a taproot key-path spend (BIP341).
fn verify_taproot_keypath(
    spending: &Tx,
    input_idx: usize,
    program: &[u8],
    stack: &[Vec<u8>],
    annex_bytes: Option<&[u8]>,
    prevouts: &[TxOut],
) -> Result<bool, ScriptError> {
    let signature_bytes = &stack[0];
    let sighash_type = match signature_bytes.len() {
        64 => Sighash::Default,
        65 => Sighash::from_consensus_u8(signature_bytes[64])
            .map_err(|error| ScriptError::Verification(error.to_string()))?,
        len => {
            return Err(ScriptError::Verification(format!(
                "taproot key-path signature length {len} is not 64 or 65 bytes"
            )));
        }
    };
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let public_key = XOnlyPublicKey::from_slice(program)
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let mut cache = SighashCache::new(spending);
    let sighash = cache
        .taproot_signature_hash(input_idx, prevouts, annex_bytes, None, sighash_type)
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let message = Message::from_digest(*sighash.as_byte_array());
    if taproot::verify_taproot_keypath(&signature, &message, &public_key) {
        Ok(true)
    } else {
        Err(ScriptError::Verification(
            "taproot key-path Schnorr verification failed".to_owned(),
        ))
    }
}

/// Verifies a taproot script-path spend (BIP341/BIP342).
fn verify_taproot_scriptpath(
    spending: &Tx,
    input_idx: usize,
    program: &[u8],
    witness: &[Vec<u8>],
    stack: &mut Vec<Vec<u8>>,
    annex_bytes: Option<Vec<u8>>,
    prevouts: &[TxOut],
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    // Core: "const valtype& control = SpanPopBack(stack); const valtype& script = SpanPopBack(stack);"
    let control = stack
        .pop()
        .ok_or_else(|| invalid(ScriptErrCode::WitnessProgramWitnessEmpty))?;
    let script = stack
        .pop()
        .ok_or_else(|| invalid(ScriptErrCode::WitnessProgramWitnessEmpty))?;

    // Core: control size validation.
    if control.len() < taproot::TAPROOT_CONTROL_BASE_SIZE
        || control.len() > taproot::TAPROOT_CONTROL_MAX_SIZE
        || !(control.len() - taproot::TAPROOT_CONTROL_BASE_SIZE)
            .is_multiple_of(taproot::TAPROOT_CONTROL_NODE_SIZE)
    {
        return Err(invalid(ScriptErrCode::TaprootWrongControlSize));
    }

    // Core: execdata.m_tapleaf_hash = ComputeTapleafHash(control[0] & TAPROOT_LEAF_MASK, script)
    let leaf_version = control[0] & taproot::TAPROOT_LEAF_MASK;
    let tapleaf = bitcoin_rs_primitives::tapleaf_hash(leaf_version, &script);

    // Core: VerifyTaprootCommitment(control, program, tapleaf_hash)
    if !taproot::verify_taproot_commitment(&control, program, &tapleaf) {
        return Err(invalid(ScriptErrCode::WitnessProgramMismatch));
    }

    // Core: if ((control[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT)
    if leaf_version != taproot::TAPROOT_LEAF_TAPSCRIPT {
        // Unknown leaf version: success by consensus, discouraged by policy.
        if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION) {
            return Err(invalid(ScriptErrCode::DiscourageUpgradableTaprootVersion));
        }
        return Ok(true);
    }

    // Build the witness stack for the evaluator: the remaining elements
    // (after annex, control, and script were popped) are the input stack.
    // Core: ExecuteWitnessScript checks stack.size() > MAX_STACK_SIZE
    // for tapscript before running EvalScript.
    if stack.len() > eval::MAX_STACK_SIZE {
        return Err(invalid(ScriptErrCode::StackSize));
    }
    let mut witness_stack = Stack::new();
    for element in &*stack {
        if element.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(invalid(ScriptErrCode::PushSize));
        }
        witness_stack
            .push(ScriptItem::Bytes(element.as_slice().into()))
            .map_err(|_| invalid(ScriptErrCode::StackSize))?;
    }

    // Core: execdata.m_validation_weight_left =
    //   GetSerializeSize(witness.stack) + VALIDATION_WEIGHT_OFFSET
    // `witness.stack` is the *original* full witness (including annex,
    // control, and script). The serialization is a CompactSize count
    // prefix followed by each element as CompactSize(len) + bytes.
    let witness_serialized_size: usize = varint_len(witness.len())
        + witness
            .iter()
            .map(|elem| varint_len(elem.len()) + elem.len())
            .sum::<usize>();
    let mut validation_weight_left = Some(
        i64::try_from(witness_serialized_size).unwrap_or(i64::MAX) + eval::VALIDATION_WEIGHT_OFFSET,
    );

    let mut checker = TxSignatureChecker::new(spending, input_idx, Amount::ZERO, prevouts);
    checker.set_annex(annex_bytes);

    eval::eval_script(
        &mut witness_stack,
        &script,
        flags,
        &mut checker,
        SigVersion::Tapscript,
        &mut validation_weight_left,
        Some(&tapleaf),
    )?;

    if witness_stack.len() != 1 {
        return Err(invalid(ScriptErrCode::CleanStack));
    }
    require_true_top(&witness_stack)?;
    Ok(true)
}

/// Returns the varint-encoded length prefix size for `data_len` bytes.
fn varint_len(data_len: usize) -> usize {
    if data_len < 0xfd {
        1
    } else if data_len <= 0xffff {
        3
    } else if data_len <= 0xffff_ffff {
        5
    } else {
        9
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };

    use super::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};

    #[test]
    fn op_true_spend_succeeds_and_a_false_stack_result_fails() {
        let interpreter = Interpreter;
        let tx = unsigned_spend();
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: vec![0x51].into(),
        };

        assert_eq!(
            interpreter.execute(
                &prevout.script_pubkey,
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &prevout,
                &tx,
                0,
            ),
            Ok(true)
        );

        // OP_0 leaves one empty element, which CastToBool reads as false.
        assert!(matches!(
            interpreter.execute(&[0x00], &[], &[], VerifyFlags::MANDATORY, &prevout, &tx, 0,),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::EvalFalse
            })
        ));
    }

    fn unsigned_spend() -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xffff_fffe),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::ZERO,
        }
    }
}
