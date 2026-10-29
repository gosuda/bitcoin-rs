//! Script verification entry points over the native transaction type.

use std::borrow::Cow;
use std::fmt;

use bitcoin_rs_primitives::{
    OutPoint, Script, SighashCache, Tx, TxOut, Witness, varint::encoded_len,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::checker::{SigVersion, TxSignatureChecker};
use crate::eval::{self, MAX_SCRIPT_ELEMENT_SIZE};
use crate::script::{is_push_only, witness_program};
use crate::signature_cache::SignatureCache;
use crate::stack::{ScriptItem, Stack};
use crate::taproot;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct VerifyFlags(u32);

impl VerifyFlags {
    pub const NONE: Self = Self(0);
    pub const P2SH: Self = Self(1 << 0);
    pub const STRICTENC: Self = Self(1 << 1);
    pub const DERSIG: Self = Self(1 << 2);
    pub const LOW_S: Self = Self(1 << 3);
    pub const NULLDUMMY: Self = Self(1 << 4);
    pub const SIGPUSHONLY: Self = Self(1 << 5);
    pub const MINIMALDATA: Self = Self(1 << 6);
    pub const DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 7);
    pub const CLEANSTACK: Self = Self(1 << 8);
    pub const CHECKLOCKTIMEVERIFY: Self = Self(1 << 9);
    pub const CHECKSEQUENCEVERIFY: Self = Self(1 << 10);
    pub const WITNESS: Self = Self(1 << 11);
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Self = Self(1 << 12);
    pub const MINIMALIF: Self = Self(1 << 13);
    pub const NULLFAIL: Self = Self(1 << 14);
    pub const WITNESS_PUBKEYTYPE: Self = Self(1 << 15);
    pub const CONST_SCRIPTCODE: Self = Self(1 << 16);
    pub const TAPROOT: Self = Self(1 << 17);
    pub const DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: Self = Self(1 << 18);
    pub const DISCOURAGE_OP_SUCCESS: Self = Self(1 << 19);
    pub const DISCOURAGE_UPGRADABLE_PUBKEYTYPE: Self = Self(1 << 20);
    pub const MANDATORY: Self = Self(
        Self::P2SH.0
            | Self::DERSIG.0
            | Self::NULLDUMMY.0
            | Self::CHECKLOCKTIMEVERIFY.0
            | Self::CHECKSEQUENCEVERIFY.0
            | Self::WITNESS.0
            | Self::TAPROOT.0,
    );
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

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn kernel_bits(self) -> u32 {
        self.0 & Self::MANDATORY.0
    }

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

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

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

macro_rules! script_errors {
    ($($variant:ident = $name:literal,)*) => {
        #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
        pub enum ScriptErrCode {
            $(
                #[doc = concat!("`SCRIPT_ERR_", $name, "`")]
                $variant,
            )*
        }

        impl fmt::Display for ScriptErrCode {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self {
                    $(Self::$variant => $name,)*
                })
            }
        }
    };
}

script_errors! {
    EvalFalse = "EVAL_FALSE",
    Verify = "VERIFY",
    EqualVerify = "EQUALVERIFY",
    CheckMultisigVerify = "CHECKMULTISIGVERIFY",
    CheckSigVerify = "CHECKSIGVERIFY",
    NumEqualVerify = "NUMEQUALVERIFY",
    ScriptSize = "SCRIPT_SIZE",
    PushSize = "PUSH_SIZE",
    OpCount = "OP_COUNT",
    StackSize = "STACK_SIZE",
    SigCount = "SIG_COUNT",
    PubkeyCount = "PUBKEY_COUNT",
    BadOpcode = "BAD_OPCODE",
    DisabledOpcode = "DISABLED_OPCODE",
    InvalidStackOperation = "INVALID_STACK_OPERATION",
    InvalidAltstackOperation = "INVALID_ALTSTACK_OPERATION",
    OpReturn = "OP_RETURN",
    UnbalancedConditional = "UNBALANCED_CONDITIONAL",
    NegativeLocktime = "NEGATIVE_LOCKTIME",
    UnsatisfiedLocktime = "UNSATISFIED_LOCKTIME",
    SigHashtype = "SIG_HASHTYPE",
    SigDer = "SIG_DER",
    MinimalData = "MINIMALDATA",
    SigPushonly = "SIG_PUSHONLY",
    SigHighS = "SIG_HIGH_S",
    SigNullDummy = "SIG_NULLDUMMY",
    MinimalIf = "MINIMALIF",
    SigNullFail = "SIG_NULLFAIL",
    DiscourageUpgradableNops = "DISCOURAGE_UPGRADABLE_NOPS",
    DiscourageUpgradableWitnessProgram = "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
    DiscourageUpgradableTaprootVersion = "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
    DiscourageOpSuccess = "DISCOURAGE_OP_SUCCESS",
    DiscourageUpgradablePubkeyType = "DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
    PubkeyType = "PUBKEYTYPE",
    CleanStack = "CLEANSTACK",
    WitnessProgramWrongLength = "WITNESS_PROGRAM_WRONG_LENGTH",
    WitnessProgramWitnessEmpty = "WITNESS_PROGRAM_WITNESS_EMPTY",
    WitnessProgramMismatch = "WITNESS_PROGRAM_MISMATCH",
    WitnessMalleated = "WITNESS_MALLEATED",
    WitnessMalleatedP2sh = "WITNESS_MALLEATED_P2SH",
    WitnessUnexpected = "WITNESS_UNEXPECTED",
    WitnessPubkeyType = "WITNESS_PUBKEYTYPE",
    SchnorrSigSize = "SCHNORR_SIG_SIZE",
    SchnorrSigHashtype = "SCHNORR_SIG_HASHTYPE",
    SchnorrSig = "SCHNORR_SIG",
    TaprootWrongControlSize = "TAPROOT_WRONG_CONTROL_SIZE",
    TapscriptValidationWeight = "TAPSCRIPT_VALIDATION_WEIGHT",
    TapscriptCheckMultiSig = "TAPSCRIPT_CHECKMULTISIG",
    TapscriptMinimalIf = "TAPSCRIPT_MINIMALIF",
    TapscriptEmptyPubkey = "TAPSCRIPT_EMPTY_PUBKEY",
    OpCodeSeparator = "OP_CODESEPARATOR",
    SigFindAndDelete = "SIG_FINDANDDELETE",
    ScriptNum = "SCRIPTNUM",
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScriptError {
    #[error("input index {index} out of range for {inputs} inputs")]
    InputIndexOutOfRange { index: usize, inputs: usize },
    #[error("unknown script verify flag {name}")]
    UnknownFlag { name: String },
    #[error("script verification failed: {0}")]
    Verification(String),
    #[error("prevout count does not match transaction input count")]
    TaprootPrevoutsUnavailable,
    #[error("script failed: {code}")]
    Invalid { code: ScriptErrCode },
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Interpreter;

impl Interpreter {
    /// `prevouts` must contain one spent output for each input, in input order.
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
        if prevouts.len() != inputs {
            return Err(ScriptError::TaprootPrevoutsUnavailable);
        }
        let input = tx
            .inputs
            .get(input_idx)
            .ok_or(ScriptError::InputIndexOutOfRange {
                index: input_idx,
                inputs,
            })?;
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
            let grafted_input = &mut grafted.inputs[input_idx];
            grafted_input.script_sig = Script::from_bytes(script_sig.to_vec());
            grafted_input.witness = Witness::from_stack(witness.to_vec());
            Cow::Owned(grafted)
        };

        let cache = SighashCache::new(&spending);
        execute_spend(
            &spending,
            input_idx,
            script_pubkey,
            flags,
            prevouts,
            &cache,
            None,
        )
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PrevoutError {
    #[error("transaction has {input_count} inputs but {prevout_count} prevouts")]
    Count {
        input_count: usize,
        prevout_count: usize,
    },
    #[error("prevout does not match transaction input {input_index}")]
    Mismatch { input_index: usize },
}

pub fn validate_prevouts(tx: &Tx, prevouts: &[(OutPoint, TxOut)]) -> Result<(), PrevoutError> {
    if prevouts.len() != tx.inputs.len() {
        return Err(PrevoutError::Count {
            input_count: tx.inputs.len(),
            prevout_count: prevouts.len(),
        });
    }
    for (input_index, (input, (outpoint, _))) in tx.inputs.iter().zip(prevouts).enumerate() {
        if input.previous_output != *outpoint {
            return Err(PrevoutError::Mismatch { input_index });
        }
    }
    Ok(())
}

pub struct PreparedTransaction<'tx> {
    tx: &'tx Tx,
    prevouts: Vec<TxOut>,
    cache: SighashCache<'tx>,
}

impl<'tx> PreparedTransaction<'tx> {
    pub fn new(tx: &'tx Tx, prevouts: &[(OutPoint, TxOut)]) -> Result<Self, PrevoutError> {
        validate_prevouts(tx, prevouts)?;
        Ok(Self {
            tx,
            prevouts: prevouts.iter().map(|(_, output)| output.clone()).collect(),
            cache: SighashCache::new(tx),
        })
    }

    pub fn from_owned(tx: &'tx Tx, prevouts: Vec<(OutPoint, TxOut)>) -> Result<Self, PrevoutError> {
        validate_prevouts(tx, &prevouts)?;
        let mut prevouts: Vec<TxOut> = prevouts.into_iter().map(|(_, output)| output).collect();
        prevouts.shrink_to_fit();
        Ok(Self {
            tx,
            prevouts,
            cache: SighashCache::new(tx),
        })
    }

    pub fn verify_input(
        &self,
        input_idx: usize,
        flags: VerifyFlags,
        cache: Option<&SignatureCache>,
    ) -> Result<bool, ScriptError> {
        let inputs = self.tx.inputs.len();
        if self.tx.inputs.get(input_idx).is_none() {
            return Err(ScriptError::InputIndexOutOfRange {
                index: input_idx,
                inputs,
            });
        }
        execute_spend(
            self.tx,
            input_idx,
            &self.prevouts[input_idx].script_pubkey,
            flags,
            &self.prevouts,
            &self.cache,
            cache,
        )
    }
}

fn execute_spend(
    spending: &Tx,
    input_idx: usize,
    script_pubkey: &[u8],
    flags: VerifyFlags,
    prevouts: &[TxOut],
    cache: &SighashCache<'_>,
    sig_cache: Option<&SignatureCache>,
) -> Result<bool, ScriptError> {
    let input = &spending.inputs[input_idx];
    let mut checker = TxSignatureChecker::new(
        spending,
        input_idx,
        prevouts[input_idx].value,
        prevouts,
        cache,
        sig_cache,
    );
    verify_script(
        &input.script_sig,
        script_pubkey,
        &input.witness,
        flags.filled(),
        &mut checker,
    )?;
    Ok(true)
}

fn invalid(code: ScriptErrCode) -> ScriptError {
    ScriptError::Invalid { code }
}

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
            if version == 1 && program.len() == 32 {
                if flags.contains(VerifyFlags::TAPROOT) {
                    verify_taproot(program, witness, flags, checker)?;
                }
                stack.clear();
                stack
                    .push(ScriptItem::Num(1))
                    .map_err(|_| invalid(ScriptErrCode::StackSize))?;
            } else {
                verify_witness_program(witness, version, program, flags, checker, &mut stack)?;
            }
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

    if flags.contains(VerifyFlags::CLEANSTACK)
        && (flags.contains(VerifyFlags::P2SH) || flags.contains(VerifyFlags::WITNESS))
    {
        if stack.len() != 1 {
            return Err(invalid(ScriptErrCode::CleanStack));
        }
    }

    Ok(())
}

fn verify_witness_program(
    witness: &[Vec<u8>],
    version: u8,
    program: &[u8],
    flags: VerifyFlags,
    checker: &TxSignatureChecker<'_>,
    stack: &mut Stack,
) -> Result<(), ScriptError> {
    if version != 0 {
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
            if Sha256::digest(script).as_slice() != program {
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

    if witness_stack.len() != 1 {
        return Err(invalid(ScriptErrCode::CleanStack));
    }
    require_true_top(&witness_stack)?;
    *stack = witness_stack;
    Ok(())
}

fn p2wpkh_script_code(program: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(5 + program.len());
    script.push(crate::script::opcode::OP_DUP);
    script.push(crate::script::opcode::OP_HASH160);
    script.push(0x14);
    script.extend_from_slice(program);
    script.push(crate::script::opcode::OP_EQUALVERIFY);
    script.push(crate::script::opcode::OP_CHECKSIG);
    script
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

fn verify_taproot(
    program: &[u8],
    witness: &[Vec<u8>],
    flags: VerifyFlags,
    checker: &mut TxSignatureChecker<'_>,
) -> Result<(), ScriptError> {
    if witness.is_empty() {
        return Err(invalid(ScriptErrCode::WitnessProgramWitnessEmpty));
    }

    let mut stack: Vec<Vec<u8>> = witness.to_vec();

    let annex_bytes = strip_annex(&mut stack);

    if stack.len() == 1 {
        let signature = &stack[0];
        if signature.is_empty() {
            return Err(invalid(ScriptErrCode::SchnorrSigSize));
        }
        checker.set_annex(annex_bytes);
        if checker.check_schnorr_signature(signature, program, None, u32::MAX)? {
            Ok(())
        } else {
            Err(invalid(ScriptErrCode::SchnorrSig))
        }
    } else {
        verify_taproot_scriptpath(checker, program, witness, &mut stack, annex_bytes, flags)
    }
}

fn strip_annex(stack: &mut Vec<Vec<u8>>) -> Option<Vec<u8>> {
    if stack.len() < 2 {
        return None;
    }
    let is_annex = stack
        .last()
        .is_some_and(|last| !last.is_empty() && last[0] == taproot::ANNEX_TAG);
    if is_annex { stack.pop() } else { None }
}

fn verify_taproot_scriptpath(
    checker: &mut TxSignatureChecker<'_>,
    program: &[u8],
    witness: &[Vec<u8>],
    stack: &mut Vec<Vec<u8>>,
    annex_bytes: Option<Vec<u8>>,
    flags: VerifyFlags,
) -> Result<(), ScriptError> {
    let control = stack
        .pop()
        .ok_or_else(|| invalid(ScriptErrCode::WitnessProgramWitnessEmpty))?;
    let script = stack
        .pop()
        .ok_or_else(|| invalid(ScriptErrCode::WitnessProgramWitnessEmpty))?;

    if control.len() < taproot::TAPROOT_CONTROL_BASE_SIZE
        || control.len() > taproot::TAPROOT_CONTROL_MAX_SIZE
        || !(control.len() - taproot::TAPROOT_CONTROL_BASE_SIZE)
            .is_multiple_of(taproot::TAPROOT_CONTROL_NODE_SIZE)
    {
        return Err(invalid(ScriptErrCode::TaprootWrongControlSize));
    }

    let leaf_version = control[0] & taproot::TAPROOT_LEAF_MASK;
    let tapleaf = bitcoin_rs_primitives::tapleaf_hash(leaf_version, &script);

    if !taproot::verify_taproot_commitment(&control, program, &tapleaf) {
        return Err(invalid(ScriptErrCode::WitnessProgramMismatch));
    }

    if leaf_version != taproot::TAPROOT_LEAF_TAPSCRIPT {
        if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION) {
            return Err(invalid(ScriptErrCode::DiscourageUpgradableTaprootVersion));
        }
        return Ok(());
    }

    if eval::tapscript_op_success(&script, flags)? {
        return Ok(());
    }

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

    let witness_serialized_size: usize =
        encoded_len(u64::try_from(witness.len()).unwrap_or(u64::MAX))
            + witness
                .iter()
                .map(|elem| encoded_len(u64::try_from(elem.len()).unwrap_or(u64::MAX)) + elem.len())
                .sum::<usize>();
    let mut validation_weight_left = Some(
        i64::try_from(witness_serialized_size).unwrap_or(i64::MAX) + eval::VALIDATION_WEIGHT_OFFSET,
    );

    checker.set_annex(annex_bytes);

    eval::eval_script(
        &mut witness_stack,
        &script,
        flags,
        checker,
        SigVersion::Tapscript,
        &mut validation_weight_left,
        Some(&tapleaf),
    )?;

    if witness_stack.len() != 1 {
        return Err(invalid(ScriptErrCode::CleanStack));
    }
    require_true_top(&witness_stack)?;
    Ok(())
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
            interpreter.execute_with_prevouts(
                &prevout.script_pubkey,
                &[],
                &[],
                VerifyFlags::MANDATORY,
                std::slice::from_ref(&prevout),
                &tx,
                0,
            ),
            Ok(true)
        );

        assert!(matches!(
            interpreter.execute_with_prevouts(
                &[0x00],
                &[],
                &[],
                VerifyFlags::MANDATORY,
                std::slice::from_ref(&prevout),
                &tx,
                0,
            ),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::EvalFalse
            })
        ));
    }

    #[test]
    fn execute_with_prevouts_rejects_a_mismatched_prevout_slice() {
        let interpreter = Interpreter;
        let tx = two_input_spend();
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: vec![0x51].into(),
        };

        let three = [prevout.clone(), prevout.clone(), prevout.clone()];
        assert_eq!(
            interpreter.execute_with_prevouts(
                &prevout.script_pubkey,
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &three,
                &tx,
                0,
            ),
            Err(ScriptError::TaprootPrevoutsUnavailable)
        );
    }

    fn two_input_spend() -> Tx {
        Tx {
            version: 2,
            inputs: vec![unsigned_input(), unsigned_input()],
            outputs: vec![TxOut {
                value: Amount::from_sat(98_000),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn unsigned_input() -> TxIn {
        TxIn {
            previous_output: OutPoint::new(Txid::default(), 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_fffe),
            witness: Witness::new(),
        }
    }

    fn unsigned_spend() -> Tx {
        Tx {
            version: 2,
            inputs: vec![unsigned_input()],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::ZERO,
        }
    }
}
