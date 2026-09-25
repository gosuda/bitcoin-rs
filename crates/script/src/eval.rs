//! The opcode evaluator: a bounded stack machine mirroring Bitcoin Core's
//! `EvalScript`.
//!
//! Behavioral authority: `.references/bitcoin/src/script/interpreter.cpp`
//! (`EvalScript`, `CheckMinimalPush`, `CScriptNum`, `FindAndDelete`). The
//! structure is idiomatic Rust rather than a transliteration: one dispatch
//! loop over [`Instruction`]s, a [`Stack`] pair for main/alt stacks, and a
//! compact condition stack. Every failing path returns a
//! [`ScriptError::Invalid`] carrying Core's `SCRIPT_ERR_*` name; nothing
//! panics on malformed input.

use std::borrow::Cow;

use bitcoin_rs_primitives::{CODESEPARATOR_POSITION, Hash256};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;

use crate::checker::{SigVersion, TxSignatureChecker};
use crate::interpreter::{ScriptErrCode, ScriptError, VerifyFlags};
use crate::script::{Instruction, instructions, opcode, push_data};
use crate::stack::{ScriptItem, Stack};

use bitcoin_hashes::{Hash as _, ripemd160, sha1};

/// `OP_NOP` (0x61).
pub const OP_NOP: u8 = 0x61;
/// `OP_IF` (0x63).
pub const OP_IF: u8 = 0x63;
/// `OP_NOTIF` (0x64).
pub const OP_NOTIF: u8 = 0x64;
/// `OP_ELSE` (0x67).
pub const OP_ELSE: u8 = 0x67;
/// `OP_ENDIF` (0x68).
pub const OP_ENDIF: u8 = 0x68;
/// `OP_VERIFY` (0x69).
pub const OP_VERIFY: u8 = 0x69;
/// `OP_RETURN` (0x6a).
pub const OP_RETURN: u8 = 0x6a;
/// `OP_TOALTSTACK` (0x6b).
pub const OP_TOALTSTACK: u8 = 0x6b;
/// `OP_FROMALTSTACK` (0x6c).
pub const OP_FROMALTSTACK: u8 = 0x6c;
/// `OP_2DROP` (0x6d).
pub const OP_2DROP: u8 = 0x6d;
/// `OP_2DUP` (0x6e).
pub const OP_2DUP: u8 = 0x6e;
/// `OP_3DUP` (0x6f).
pub const OP_3DUP: u8 = 0x6f;
/// `OP_2OVER` (0x70).
pub const OP_2OVER: u8 = 0x70;
/// `OP_2ROT` (0x71).
pub const OP_2ROT: u8 = 0x71;
/// `OP_2SWAP` (0x72).
pub const OP_2SWAP: u8 = 0x72;
/// `OP_IFDUP` (0x73).
pub const OP_IFDUP: u8 = 0x73;
/// `OP_DEPTH` (0x74).
pub const OP_DEPTH: u8 = 0x74;
/// `OP_DROP` (0x75).
pub const OP_DROP: u8 = 0x75;
/// `OP_DUP` (0x76).
pub const OP_DUP: u8 = 0x76;
/// `OP_NIP` (0x77).
pub const OP_NIP: u8 = 0x77;
/// `OP_OVER` (0x78).
pub const OP_OVER: u8 = 0x78;
/// `OP_PICK` (0x79).
pub const OP_PICK: u8 = 0x79;
/// `OP_ROLL` (0x7a).
pub const OP_ROLL: u8 = 0x7a;
/// `OP_ROT` (0x7b).
pub const OP_ROT: u8 = 0x7b;
/// `OP_SWAP` (0x7c).
pub const OP_SWAP: u8 = 0x7c;
/// `OP_TUCK` (0x7d).
pub const OP_TUCK: u8 = 0x7d;
/// `OP_SIZE` (0x82).
pub const OP_SIZE: u8 = 0x82;
/// `OP_EQUAL` (0x87).
pub const OP_EQUAL: u8 = 0x87;
/// `OP_EQUALVERIFY` (0x88).
pub const OP_EQUALVERIFY: u8 = 0x88;
/// `OP_1NEGATE` (0x4f).
pub const OP_1NEGATE: u8 = 0x4f;
/// `OP_1ADD` (0x8b).
pub const OP_1ADD: u8 = 0x8b;
/// `OP_1SUB` (0x8c).
pub const OP_1SUB: u8 = 0x8c;
/// `OP_NEGATE` (0x8f).
pub const OP_NEGATE: u8 = 0x8f;
/// `OP_ABS` (0x90).
pub const OP_ABS: u8 = 0x90;
/// `OP_NOT` (0x91).
pub const OP_NOT: u8 = 0x91;
/// `OP_0NOTEQUAL` (0x92).
pub const OP_0NOTEQUAL: u8 = 0x92;
/// `OP_ADD` (0x93).
pub const OP_ADD: u8 = 0x93;
/// `OP_SUB` (0x94).
pub const OP_SUB: u8 = 0x94;
/// `OP_BOOLAND` (0x9a).
pub const OP_BOOLAND: u8 = 0x9a;
/// `OP_BOOLOR` (0x9b).
pub const OP_BOOLOR: u8 = 0x9b;
/// `OP_NUMEQUAL` (0x9c).
pub const OP_NUMEQUAL: u8 = 0x9c;
/// `OP_NUMEQUALVERIFY` (0x9d).
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
/// `OP_NUMNOTEQUAL` (0x9e).
pub const OP_NUMNOTEQUAL: u8 = 0x9e;
/// `OP_LESSTHAN` (0x9f).
pub const OP_LESSTHAN: u8 = 0x9f;
/// `OP_GREATERTHAN` (0xa0).
pub const OP_GREATERTHAN: u8 = 0xa0;
/// `OP_LESSTHANOREQUAL` (0xa1).
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
/// `OP_GREATERTHANOREQUAL` (0xa2).
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
/// `OP_MIN` (0xa3).
pub const OP_MIN: u8 = 0xa3;
/// `OP_MAX` (0xa4).
pub const OP_MAX: u8 = 0xa4;
/// `OP_WITHIN` (0xa5).
pub const OP_WITHIN: u8 = 0xa5;
/// `OP_RIPEMD160` (0xa6).
pub const OP_RIPEMD160: u8 = 0xa6;
/// `OP_SHA1` (0xa7).
pub const OP_SHA1: u8 = 0xa7;
/// `OP_SHA256` (0xa8).
pub const OP_SHA256: u8 = 0xa8;
/// `OP_HASH160` (0xa9).
pub const OP_HASH160: u8 = 0xa9;
/// `OP_HASH256` (0xaa).
pub const OP_HASH256: u8 = 0xaa;
/// `OP_CODESEPARATOR` (0xab).
pub const OP_CODESEPARATOR: u8 = 0xab;
/// `OP_CHECKSIG` (0xac).
pub const OP_CHECKSIG: u8 = 0xac;
/// `OP_CHECKSIGVERIFY` (0xad).
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
/// `OP_CHECKMULTISIG` (0xae).
pub const OP_CHECKMULTISIG: u8 = 0xae;
/// `OP_CHECKMULTISIGVERIFY` (0xaf).
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
/// `OP_NOP1` (0xb0).
pub const OP_NOP1: u8 = 0xb0;
/// `OP_CHECKLOCKTIMEVERIFY` (0xb1).
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
/// `OP_CHECKSEQUENCEVERIFY` (0xb2).
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
/// `OP_NOP4` (0xb3).
pub const OP_NOP4: u8 = 0xb3;
/// `OP_NOP5` (0xb4).
pub const OP_NOP5: u8 = 0xb4;
/// `OP_NOP6` (0xb5).
pub const OP_NOP6: u8 = 0xb5;
/// `OP_NOP7` (0xb6).
pub const OP_NOP7: u8 = 0xb6;
/// `OP_NOP8` (0xb7).
pub const OP_NOP8: u8 = 0xb7;
/// `OP_NOP9` (0xb8).
pub const OP_NOP9: u8 = 0xb8;
/// `OP_NOP10` (0xb9).
pub const OP_NOP10: u8 = 0xb9;
/// `OP_CHECKSIGADD` (0xba), tapscript only.
pub const OP_CHECKSIGADD: u8 = 0xba;

/// Maximum serialized script size accepted for `Base`/`WitnessV0` evaluation.
pub const MAX_SCRIPT_SIZE: usize = 10_000;
/// Maximum size of one pushed stack element.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// Maximum non-push opcodes per script.
pub const MAX_OPS_PER_SCRIPT: usize = 201;
/// Maximum public keys in a bare multisig.
pub(crate) const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
/// Maximum combined depth of the main and alt stacks.
pub const MAX_STACK_SIZE: usize = 1000;
/// Bytes per passed signature charged against BIP342's validation weight.
pub(crate) const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;
/// BIP342 validation-weight offset accounting for the witness itself.
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Byte slice view of a stack item, in script-encoding terms.
type Bytes = SmallVec<[u8; 32]>;

/// A condition stack mirroring Core's `ConditionStack`: tracks only whether
/// every open `IF` level is executing.
struct ConditionStack {
    /// Levels currently open; the top is the innermost.
    all_true: bool,
    /// Position (from the bottom) of the first `false` level, if any.
    first_false: Option<usize>,
    size: usize,
}

impl ConditionStack {
    fn new() -> Self {
        Self {
            all_true: true,
            first_false: None,
            size: 0,
        }
    }

    fn all_true(&self) -> bool {
        self.all_true
    }

    fn is_empty(&self) -> bool {
        self.size == 0
    }

    fn push(&mut self, value: bool) {
        if self.first_false.is_none() && !value {
            self.first_false = Some(self.size);
            self.all_true = false;
        }
        self.size += 1;
    }

    fn pop(&mut self) {
        self.size -= 1;
        if self.first_false == Some(self.size) {
            self.first_false = None;
            self.all_true = true;
        }
    }

    fn toggle_top(&mut self) {
        match self.first_false {
            None => {
                self.first_false = Some(self.size - 1);
                self.all_true = false;
            }
            Some(pos) if pos == self.size - 1 => {
                self.first_false = None;
                self.all_true = true;
            }
            Some(_) => {}
        }
    }
}

/// Core's `CScriptNum`: little-endian sign-magnitude script numbers.
///
/// `max_size` bounds the encoded length (4 bytes normally, 5 for CLTV/CSV
/// operands). Non-minimal encodings are rejected only under
/// `f_require_minimal`. Malformed input maps to `SCRIPT_ERR_SCRIPTNUM`.
fn script_num(bytes: &[u8], require_minimal: bool, max_size: usize) -> Result<i64, ScriptError> {
    if bytes.len() > max_size {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::ScriptNum,
        });
    }
    if require_minimal && !bytes.is_empty() {
        // Check that the number is encoded with the minimum possible number
        // of bytes: the most significant byte must not be a redundant sign
        // extension (this also rejects the negative-zero encoding 0x80).
        let last = bytes.last().copied().unwrap_or(0);
        if last.trailing_zeros() >= 7 {
            let second_to_last_significant = bytes.len() > 1 && bytes[bytes.len() - 2] & 0x80 != 0;
            if bytes.len() == 1 || !second_to_last_significant {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::ScriptNum,
                });
            }
        }
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut value: u64 = 0;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (8 * index);
    }
    if bytes[bytes.len() - 1] & 0x80 != 0 {
        let mask = !(0x80_u64 << (8 * (bytes.len() - 1)));
        let magnitude = value & mask;
        // A 5-byte negative number can exceed i64's positive range in raw
        // form but its magnitude is at most 2^39-1, so the negation fits.
        let magnitude = i64::try_from(magnitude).map_err(|_| ScriptError::Invalid {
            code: ScriptErrCode::ScriptNum,
        })?;
        Ok(-magnitude)
    } else {
        i64::try_from(value).map_err(|_| ScriptError::Invalid {
            code: ScriptErrCode::ScriptNum,
        })
    }
}

/// Core's `CScriptNum::serialize`.
fn script_num_serialize(value: i64) -> Bytes {
    if value == 0 {
        return SmallVec::new();
    }
    let negative = value < 0;
    // `unsigned_abs` returns u64: |i64::MIN| is exactly representable, no
    // conversion can fail.
    let mut abs = value.unsigned_abs();
    let mut result = SmallVec::new();
    while abs > 0 {
        result.push(abs.to_le_bytes()[0]);
        abs >>= 8;
    }
    if result.last().is_some_and(|byte| byte & 0x80 != 0) {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        if let Some(last) = result.last_mut() {
            *last |= 0x80;
        }
    }
    result
}

/// Core's `CastToBool`: any nonzero byte makes the item true, except the
/// single-byte negative-zero encoding `0x80`.
fn cast_to_bool(bytes: &[u8]) -> bool {
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != 0 {
            // Can be negative zero.
            return !(index == bytes.len() - 1 && *byte == 0x80);
        }
    }
    false
}

/// Core's `CastToBool` over a stack item: the truth test every script
/// terminator and conditional uses.
#[must_use]
pub fn item_is_true(item: &ScriptItem) -> bool {
    cast_to_bool(&item_bytes(item))
}

/// Converts a [`ScriptItem`] to its byte representation.
fn item_bytes(item: &ScriptItem) -> Cow<'_, [u8]> {
    match item {
        ScriptItem::Num(n) => Cow::Owned(script_num_serialize(*n).into_vec()),
        ScriptItem::Bytes(bytes) => Cow::Borrowed(bytes),
    }
}

/// Executes `script` against `stack`, mirroring Core's `EvalScript`.
///
/// `find_and_delete` controls Core's `FindAndDelete(scriptCode, sig)` for
/// `SigVersion::Base` only; callers pass the bytes to strip.
#[expect(
    clippy::too_many_lines,
    reason = "one dispatch arm per opcode family mirrors Core's EvalScript switch; \
              splitting arms into helpers would obscure the shared state flow"
)]
pub fn eval_script(
    stack: &mut Stack,
    script: &[u8],
    flags: VerifyFlags,
    checker: &mut TxSignatureChecker<'_>,
    sigversion: SigVersion,
    validation_weight_left: &mut Option<i64>,
    tapleaf_hash: Option<&Hash256>,
) -> Result<(), ScriptError> {
    debug_assert!(
        matches!(
            sigversion,
            SigVersion::Base | SigVersion::WitnessV0 | SigVersion::Tapscript
        ),
        "taproot key-path admits no script execution"
    );

    // BIP342: OP_SUCCESSx opcodes make the script unconditionally valid.
    // This scan runs before any other check (including stack element size
    // limits) and overrides everything. Mirrors Core's ExecuteWitnessScript.
    if sigversion == SigVersion::Tapscript {
        for parsed in instructions(script) {
            let op = match parsed {
                Ok(Instruction::Op(op)) => op,
                Ok(Instruction::PushBytes(_)) => continue,
                Err(_) => {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::BadOpcode,
                    });
                }
            };
            if is_op_success(op) {
                if flags.contains(VerifyFlags::DISCOURAGE_OP_SUCCESS) {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::DiscourageOpSuccess,
                    });
                }
                return Ok(());
            }
        }
    }

    if (sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0)
        && script.len() > MAX_SCRIPT_SIZE
    {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::ScriptSize,
        });
    }

    let require_minimal = flags.contains(VerifyFlags::MINIMALDATA);
    let mut conditions = ConditionStack::new();
    let mut altstack = Stack::new();
    let mut op_count: usize = 0;
    let mut codeseparator_pos: u32 = CODESEPARATOR_POSITION;
    // Byte offset of the instruction start, tracked for codeseparator
    // positioning relative to the whole script.
    let mut instruction_start: usize = 0;
    let mut remaining = script;

    while let Some(parsed) = instructions(remaining).next() {
        let instruction = match parsed {
            Ok(instruction) => instruction,
            // Core's GetOp returning false is a BAD_OPCODE.
            Err(_) => {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::BadOpcode,
                });
            }
        };
        let opcode_byte = match instruction {
            Instruction::PushBytes(data) => {
                let opcode_byte = push_opcode_for(remaining)?;
                // Core checks push size unconditionally (interpreter.cpp:457),
                // before testing fExec — a >520-byte push in a non-executed
                // branch is still PUSH_SIZE.
                if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::PushSize,
                    });
                }
                if conditions.all_true() {
                    // Core checks MINIMALDATA only in executed branches
                    // (interpreter.cpp:489, inside `if (fExec && ... <= OP_PUSHDATA4)`).
                    if flags.contains(VerifyFlags::MINIMALDATA)
                        && !check_minimal_push(data, opcode_byte)
                    {
                        return Err(ScriptError::Invalid {
                            code: ScriptErrCode::MinimalData,
                        });
                    }
                    push_bytes(stack, data)?;
                }
                advance(&mut remaining, opcode_byte, data.len());
                instruction_start = script.len() - remaining.len();
                continue;
            }
            Instruction::Op(op) => op,
        };

        let executed_push = opcode_byte <= opcode::OP_PUSHDATA4;
        if executed_push {
            // Handled above; unreachable for Op(_) variant, kept for parity.
            advance(&mut remaining, opcode_byte, 0);
            continue;
        }

        if sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0 {
            // OP_RESERVED does not count towards the opcode limit.
            if opcode_byte > opcode::OP_PUSHNUM_16 {
                op_count += 1;
                if op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::OpCount,
                    });
                }
            }
        }

        if is_disabled(opcode_byte) {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::DisabledOpcode,
            });
        }

        // With CONST_SCRIPTCODE, OP_CODESEPARATOR in non-segwit script is
        // rejected even in an unexecuted branch.
        if opcode_byte == OP_CODESEPARATOR
            && sigversion == SigVersion::Base
            && flags.contains(VerifyFlags::CONST_SCRIPTCODE)
        {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::OpCodeSeparator,
            });
        }

        let f_exec = conditions.all_true();
        if f_exec || (OP_IF..=OP_ENDIF).contains(&opcode_byte) {
            dispatch(
                opcode_byte,
                f_exec,
                stack,
                &mut altstack,
                &mut conditions,
                &mut op_count,
                require_minimal,
                flags,
                checker,
                sigversion,
                validation_weight_left,
                &mut codeseparator_pos,
                instruction_start,
                tapleaf_hash,
                script,
            )?;
        }

        if stack.len() + altstack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            });
        }

        advance(&mut remaining, opcode_byte, 0);
        instruction_start = script.len() - remaining.len();
    }

    if !conditions.is_empty() {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::UnbalancedConditional,
        });
    }
    Ok(())
}

/// Advances `remaining` past the instruction that starts with `op` and, for
/// pushes, carries `data_len` payload bytes.
fn advance(remaining: &mut &[u8], op: u8, data_len: usize) {
    let header = if (0x01..=0x4b).contains(&op) {
        1
    } else {
        match op {
            opcode::OP_PUSHDATA1 => 2,
            opcode::OP_PUSHDATA2 => 3,
            opcode::OP_PUSHDATA4 => 5,
            _ => 1,
        }
    };
    *remaining = remaining.get(header + data_len..).unwrap_or_default();
}

/// Returns the push opcode byte at the head of `remaining` for a
/// `PushBytes` instruction, reconstructing it from the length encoding.
fn push_opcode_for(remaining: &[u8]) -> Result<u8, ScriptError> {
    let head = remaining.first().copied().ok_or(ScriptError::Invalid {
        code: ScriptErrCode::BadOpcode,
    })?;
    if (0x01..=0x4b).contains(&head) {
        Ok(head)
    } else {
        match head {
            opcode::OP_PUSHDATA1 | opcode::OP_PUSHDATA2 | opcode::OP_PUSHDATA4 | opcode::OP_0 => {
                Ok(head)
            }
            _ => Err(ScriptError::Invalid {
                code: ScriptErrCode::BadOpcode,
            }),
        }
    }
}

/// Pushes raw bytes as a stack item, bounding the stack.
fn push_bytes(stack: &mut Stack, data: &[u8]) -> Result<(), ScriptError> {
    stack
        .push(ScriptItem::Bytes(SmallVec::from_slice(data)))
        .map_err(|_| ScriptError::Invalid {
            code: ScriptErrCode::StackSize,
        })
}

/// Core's disabled opcode set (CVE-2010-5137).
const fn is_disabled(op: u8) -> bool {
    matches!(
        op,
        0x7e // OP_CAT
            | 0x7f // OP_SUBSTR
            | 0x80 // OP_LEFT
            | 0x81 // OP_RIGHT
            | 0x83 // OP_INVERT
            | 0x84 // OP_AND
            | 0x85 // OP_OR
            | 0x86 // OP_XOR
            | 0x8d // OP_2MUL
            | 0x8e // OP_2DIV
            | 0x95 // OP_MUL
            | 0x96 // OP_DIV
            | 0x97 // OP_MOD
            | 0x98 // OP_LSHIFT
            | 0x99 // OP_RSHIFT
    )
}

/// BIP342 `OP_SUCCESSx` opcodes (Core's `IsOpSuccess`). A script containing
/// any of these is unconditionally valid under tapscript.
const fn is_op_success(op: u8) -> bool {
    op == 80
        || op == 98
        || (op >= 126 && op <= 129)
        || (op >= 131 && op <= 134)
        || (op >= 137 && op <= 138)
        || (op >= 141 && op <= 142)
        || (op >= 149 && op <= 153)
        || (op >= 187 && op <= 254)
}

/// Core's `CheckMinimalPush`.
fn check_minimal_push(data: &[u8], op: u8) -> bool {
    if data.is_empty() {
        // Should have used OP_0.
        return op == opcode::OP_0;
    }
    let first = data.first().copied().unwrap_or(0);
    if data.len() == 1 && (1..=16).contains(&first) {
        // Should have used OP_1 .. OP_16.
        return false;
    }
    if data.len() == 1 && first == 0x81 {
        // Should have used OP_1NEGATE.
        return false;
    }
    if data.len() <= 75 {
        // Must have used a direct push.
        return usize::from(op) == data.len();
    }
    if data.len() <= 255 {
        return op == opcode::OP_PUSHDATA1;
    }
    if data.len() <= 65535 {
        return op == opcode::OP_PUSHDATA2;
    }
    true
}

/// Executes one opcode. `f_exec` reports whether the enclosing conditional
/// stack is active; most arms are skipped otherwise, but `IF`-family
/// opcodes still drive the condition stack.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per opcode mirrors Core's EvalScript switch; splitting \
              families into helpers would fragment the shared op-count and \
              codeseparator state"
)]
#[allow(clippy::too_many_arguments)]
fn dispatch(
    op: u8,
    f_exec: bool,
    stack: &mut Stack,
    altstack: &mut Stack,
    conditions: &mut ConditionStack,
    op_count: &mut usize,
    require_minimal: bool,
    flags: VerifyFlags,
    checker: &mut TxSignatureChecker<'_>,
    sigversion: SigVersion,
    validation_weight_left: &mut Option<i64>,
    codeseparator_pos: &mut u32,
    instruction_start: usize,
    tapleaf_hash: Option<&Hash256>,
    script: &[u8],
) -> Result<(), ScriptError> {
    if !f_exec && !(OP_IF..=OP_ENDIF).contains(&op) {
        return Ok(());
    }
    let invalid_stack = || ScriptError::Invalid {
        code: ScriptErrCode::InvalidStackOperation,
    };

    // Push value: OP_1NEGATE and the OP_1..OP_16 small integers. OP_RESERVED
    // (0x50) sits between them and pushes nothing - it falls through to the
    // dispatch below, where an executed OP_RESERVED is a BAD_OPCODE.
    if op == OP_1NEGATE {
        push_bytes(stack, &script_num_serialize(-1))?;
        return Ok(());
    }
    if let Some(value) = crate::script::opcode::decode_pushnum(op) {
        push_bytes(stack, &script_num_serialize(i64::from(value)))?;
        return Ok(());
    }

    match op {
        OP_NOP => {}
        OP_CHECKLOCKTIMEVERIFY => {
            if flags.contains(VerifyFlags::CHECKLOCKTIMEVERIFY) {
                let top = stack.peek().map_err(|_| invalid_stack())?;
                let locktime = script_num(&item_bytes(top), require_minimal, 5)?;
                if locktime < 0 {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::NegativeLocktime,
                    });
                }
                if !checker.check_locktime(locktime) {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::UnsatisfiedLocktime,
                    });
                }
            } else {
                // Not enabled; treat as NOP2.
            }
        }
        OP_CHECKSEQUENCEVERIFY => {
            if flags.contains(VerifyFlags::CHECKSEQUENCEVERIFY) {
                let top = stack.peek().map_err(|_| invalid_stack())?;
                let sequence = script_num(&item_bytes(top), require_minimal, 5)?;
                if sequence < 0 {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::NegativeLocktime,
                    });
                }
                // Disabled-flag operands behave as a NOP.
                if sequence & (1 << 31) == 0 && !checker.check_sequence(sequence) {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::UnsatisfiedLocktime,
                    });
                }
            } else {
                // Not enabled; treat as NOP3.
            }
        }
        OP_NOP1 | OP_NOP4..=OP_NOP10 => {
            if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::DiscourageUpgradableNops,
                });
            }
        }
        OP_IF | OP_NOTIF => {
            let value = if f_exec {
                let top = stack.pop().map_err(|_| invalid_stack())?;
                let bytes = item_bytes(&top).into_owned();
                if sigversion == SigVersion::Tapscript {
                    if bytes.len() > 1 || (bytes.len() == 1 && bytes[0] != 1) {
                        return Err(ScriptError::Invalid {
                            code: ScriptErrCode::TapscriptMinimalIf,
                        });
                    }
                }
                if sigversion == SigVersion::WitnessV0
                    && flags.contains(VerifyFlags::MINIMALIF)
                    && (bytes.len() > 1 || (bytes.len() == 1 && bytes[0] != 1))
                {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::MinimalIf,
                    });
                }
                let parsed = cast_to_bool(&bytes);
                if op == OP_NOTIF { !parsed } else { parsed }
            } else {
                false
            };
            conditions.push(value);
        }
        OP_ELSE => {
            if conditions.is_empty() {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::UnbalancedConditional,
                });
            }
            conditions.toggle_top();
        }
        OP_ENDIF => {
            if conditions.is_empty() {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::UnbalancedConditional,
                });
            }
            conditions.pop();
        }
        OP_VERIFY => {
            let top = stack.pop().map_err(|_| invalid_stack())?;
            let bytes = item_bytes(&top).into_owned();
            if cast_to_bool(&bytes) {
                // Popped above; success leaves the stack unchanged.
            } else {
                stack.push(top).map_err(|_| ScriptError::Invalid {
                    code: ScriptErrCode::StackSize,
                })?;
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::Verify,
                });
            }
        }
        OP_RETURN => {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::OpReturn,
            });
        }
        OP_TOALTSTACK => {
            let top = stack.pop().map_err(|_| invalid_stack())?;
            altstack.push(top).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::InvalidAltstackOperation,
            })?;
        }
        OP_FROMALTSTACK => {
            let top = altstack.pop().map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::InvalidAltstackOperation,
            })?;
            push_bytes(stack, &item_bytes(&top))?;
        }
        OP_2DROP => {
            stack.pop().map_err(|_| invalid_stack())?;
            stack.pop().map_err(|_| invalid_stack())?;
        }
        OP_2DUP => {
            let second = stack.peek_at(1).map_err(|_| invalid_stack())?.clone();
            let first = stack.peek().map_err(|_| invalid_stack())?.clone();
            stack.push(second).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
            stack.push(first).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
        }
        OP_3DUP => {
            let third = stack.peek_at(2).map_err(|_| invalid_stack())?.clone();
            let second = stack.peek_at(1).map_err(|_| invalid_stack())?.clone();
            let first = stack.peek().map_err(|_| invalid_stack())?.clone();
            stack.push(third).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
            stack.push(second).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
            stack.push(first).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
        }
        OP_2OVER => {
            // Core: push stacktop(-4) then stacktop(-3) — the pair two positions
            // below the top, in their original order.
            let pair_first = stack.peek_at(3).map_err(|_| invalid_stack())?.clone();
            let pair_second = stack.peek_at(2).map_err(|_| invalid_stack())?.clone();
            stack.push(pair_first).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
            stack.push(pair_second).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
        }
        OP_2ROT => {
            let top_six = stack.drain(6).map_err(|_| invalid_stack())?;
            let x1 = top_six.first().cloned().unwrap_or_default();
            let x2 = top_six.get(1).cloned().unwrap_or_default();
            for item in top_six.into_iter().skip(2) {
                stack.push(item).map_err(|_| ScriptError::Invalid {
                    code: ScriptErrCode::StackSize,
                })?;
            }
            stack.push(x1).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
            stack.push(x2).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
        }
        OP_2SWAP => {
            // Core: swap(stacktop(-4), stacktop(-3)) then swap(stacktop(-2),
            // stacktop(-1)) — two independent pair swaps.
            stack.swap_at(3, 1).map_err(|_| invalid_stack())?;
            stack.swap_at(2, 0).map_err(|_| invalid_stack())?;
        }
        OP_IFDUP => {
            let top = stack.peek().map_err(|_| invalid_stack())?;
            let bytes = item_bytes(top).into_owned();
            if cast_to_bool(&bytes) {
                let copy = top.clone();
                stack.push(copy).map_err(|_| ScriptError::Invalid {
                    code: ScriptErrCode::StackSize,
                })?;
            }
        }
        OP_DEPTH => {
            let depth = script_num_serialize(i64::try_from(stack.len()).map_err(|_| {
                ScriptError::Invalid {
                    code: ScriptErrCode::StackSize,
                }
            })?);
            push_bytes(stack, &depth)?;
        }
        OP_DROP => {
            stack.pop().map_err(|_| invalid_stack())?;
        }
        OP_DUP => {
            let top = stack.peek().map_err(|_| invalid_stack())?.clone();
            stack.push(top).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
        }
        OP_NIP => {
            let top = stack.pop().map_err(|_| invalid_stack())?;
            stack.remove_at(0).map_err(|_| invalid_stack())?;
            stack.push(top).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
        }
        OP_OVER => {
            let second = stack.peek_at(1).map_err(|_| invalid_stack())?.clone();
            stack.push(second).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
        }
        OP_PICK | OP_ROLL => {
            let n_item = stack.pop().map_err(|_| invalid_stack())?;
            let n = script_num(&item_bytes(&n_item), require_minimal, 4)?;
            let depth = if n < 0 {
                return Err(invalid_stack());
            } else {
                usize::try_from(n).map_err(|_| invalid_stack())?
            };
            if depth >= stack.len() {
                return Err(invalid_stack());
            }
            if op == OP_PICK {
                let item = stack.peek_at(depth).map_err(|_| invalid_stack())?.clone();
                stack.push(item).map_err(|_| ScriptError::Invalid {
                    code: ScriptErrCode::StackSize,
                })?;
            } else {
                let item = stack.remove_at(depth).map_err(|_| invalid_stack())?;
                stack.push(item).map_err(|_| ScriptError::Invalid {
                    code: ScriptErrCode::StackSize,
                })?;
            }
        }
        OP_ROT => {
            let x1 = stack.remove_at(2).map_err(|_| invalid_stack())?;
            stack.push(x1).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })?;
        }
        OP_SWAP => {
            stack.swap().map_err(|_| invalid_stack())?;
        }
        OP_TUCK => {
            let top = stack.peek().map_err(|_| invalid_stack())?.clone();
            stack.insert_at(2, top).map_err(|_| invalid_stack())?;
        }
        OP_SIZE => {
            let top = stack.peek().map_err(|_| invalid_stack())?;
            let size =
                script_num_serialize(i64::try_from(item_bytes(top).len()).map_err(|_| {
                    ScriptError::Invalid {
                        code: ScriptErrCode::PushSize,
                    }
                })?);
            push_bytes(stack, &size)?;
        }
        OP_EQUAL | OP_EQUALVERIFY => {
            let second = stack.pop().map_err(|_| invalid_stack())?;
            let first = stack.pop().map_err(|_| invalid_stack())?;
            let equal = item_bytes(&first) == item_bytes(&second);
            push_bytes(stack, if equal { &[1] } else { &[] })?;
            if op == OP_EQUALVERIFY {
                if equal {
                    stack.pop().map_err(|_| invalid_stack())?;
                } else {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::EqualVerify,
                    });
                }
            }
        }
        OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
            let top = stack.pop().map_err(|_| invalid_stack())?;
            let value = script_num(&item_bytes(&top), require_minimal, 4)?;
            let result = match op {
                OP_1ADD => value.checked_add(1),
                OP_1SUB => value.checked_sub(1),
                OP_NEGATE => value.checked_neg(),
                OP_ABS => Some(value.abs()),
                OP_NOT => Some(i64::from(value == 0)),
                _ => Some(i64::from(value != 0)),
            }
            .ok_or(ScriptError::Invalid {
                code: ScriptErrCode::ScriptNum,
            })?;
            push_bytes(stack, &script_num_serialize(result))?;
        }
        OP_ADD
        | OP_SUB
        | OP_BOOLAND
        | OP_BOOLOR
        | OP_NUMEQUAL
        | OP_NUMEQUALVERIFY
        | OP_NUMNOTEQUAL
        | OP_LESSTHAN
        | OP_GREATERTHAN
        | OP_LESSTHANOREQUAL
        | OP_GREATERTHANOREQUAL
        | OP_MIN
        | OP_MAX => {
            let second = stack.pop().map_err(|_| invalid_stack())?;
            let first = stack.pop().map_err(|_| invalid_stack())?;
            let b1 = script_num(&item_bytes(&first), require_minimal, 4)?;
            let b2 = script_num(&item_bytes(&second), require_minimal, 4)?;
            let result = match op {
                OP_ADD => b1.checked_add(b2),
                OP_SUB => b1.checked_sub(b2),
                OP_BOOLAND => Some(i64::from(b1 != 0 && b2 != 0)),
                OP_BOOLOR => Some(i64::from(b1 != 0 || b2 != 0)),
                OP_NUMEQUAL | OP_NUMEQUALVERIFY => Some(i64::from(b1 == b2)),
                OP_NUMNOTEQUAL => Some(i64::from(b1 != b2)),
                OP_LESSTHAN => Some(i64::from(b1 < b2)),
                OP_GREATERTHAN => Some(i64::from(b1 > b2)),
                OP_LESSTHANOREQUAL => Some(i64::from(b1 <= b2)),
                OP_GREATERTHANOREQUAL => Some(i64::from(b1 >= b2)),
                OP_MIN => Some(b1.min(b2)),
                _ => Some(b1.max(b2)),
            }
            .ok_or(ScriptError::Invalid {
                code: ScriptErrCode::ScriptNum,
            })?;
            push_bytes(stack, &script_num_serialize(result))?;
            if op == OP_NUMEQUALVERIFY {
                let top = stack.peek().map_err(|_| invalid_stack())?;
                let bytes = item_bytes(top).into_owned();
                if cast_to_bool(&bytes) {
                    stack.pop().map_err(|_| invalid_stack())?;
                } else {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::NumEqualVerify,
                    });
                }
            }
        }
        OP_WITHIN => {
            let third = stack.pop().map_err(|_| invalid_stack())?;
            let second = stack.pop().map_err(|_| invalid_stack())?;
            let first = stack.pop().map_err(|_| invalid_stack())?;
            let x = script_num(&item_bytes(&first), require_minimal, 4)?;
            let min = script_num(&item_bytes(&second), require_minimal, 4)?;
            let max = script_num(&item_bytes(&third), require_minimal, 4)?;
            let within = min <= x && x < max;
            push_bytes(stack, if within { &[1] } else { &[] })?;
        }
        OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
            let top = stack.pop().map_err(|_| invalid_stack())?;
            let bytes = item_bytes(&top).into_owned();
            let digest = hash_bytes(op, &bytes);
            push_bytes(stack, &digest)?;
        }
        OP_CODESEPARATOR => {
            // Core sets pbegincodehash = pc (the byte *after* the CODESEPARATOR
            // opcode, since GetOp already advanced pc). The scriptCode for
            // sighash must start after the CODESEPARATOR byte, not at it.
            *codeseparator_pos =
                u32::try_from(instruction_start + 1).map_err(|_| ScriptError::Invalid {
                    code: ScriptErrCode::ScriptSize,
                })?;
        }
        OP_CHECKSIG | OP_CHECKSIGVERIFY => {
            let pubkey = stack.pop().map_err(|_| invalid_stack())?;
            let sig = stack.pop().map_err(|_| invalid_stack())?;
            let success = eval_checksig(
                &item_bytes(&sig),
                &item_bytes(&pubkey),
                instruction_start,
                *codeseparator_pos,
                script,
                flags,
                checker,
                sigversion,
                validation_weight_left,
                tapleaf_hash,
            )?;
            push_bytes(stack, if success { &[1] } else { &[] })?;
            if op == OP_CHECKSIGVERIFY {
                if success {
                    stack.pop().map_err(|_| invalid_stack())?;
                } else {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::CheckSigVerify,
                    });
                }
            }
        }
        OP_CHECKSIGADD => {
            if sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0 {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::BadOpcode,
                });
            }
            let pubkey = stack.pop().map_err(|_| invalid_stack())?;
            let num = stack.pop().map_err(|_| invalid_stack())?;
            let sig = stack.pop().map_err(|_| invalid_stack())?;
            let value = script_num(&item_bytes(&num), require_minimal, 4)?;
            let success = eval_checksig(
                &item_bytes(&sig),
                &item_bytes(&pubkey),
                instruction_start,
                *codeseparator_pos,
                script,
                flags,
                checker,
                sigversion,
                validation_weight_left,
                tapleaf_hash,
            )?;
            let result = value
                .checked_add(i64::from(success))
                .ok_or(ScriptError::Invalid {
                    code: ScriptErrCode::ScriptNum,
                })?;
            push_bytes(stack, &script_num_serialize(result))?;
        }
        OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
            if sigversion == SigVersion::Tapscript {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::TapscriptCheckMultiSig,
                });
            }
            check_multisig(
                stack,
                require_minimal,
                flags,
                checker,
                sigversion,
                op_count,
                *codeseparator_pos,
                instruction_start,
                script,
                op == OP_CHECKMULTISIGVERIFY,
            )?;
        }
        _ => {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::BadOpcode,
            });
        }
    }
    Ok(())
}

/// Computes the digest for a hash opcode.
fn hash_bytes(op: u8, data: &[u8]) -> SmallVec<[u8; 32]> {
    match op {
        OP_RIPEMD160 => SmallVec::from_slice(&ripemd160::Hash::hash(data)[..]),
        OP_SHA1 => SmallVec::from_slice(&sha1::Hash::hash(data)[..]),
        OP_SHA256 => {
            let mut engine = Sha256::new();
            Digest::update(&mut engine, data);
            SmallVec::from_slice(&Digest::finalize(engine))
        }
        OP_HASH160 => {
            let sha = sha2::Sha256::digest(data);
            SmallVec::from_slice(&ripemd160::Hash::hash(&sha)[..])
        }
        _ => {
            let once = sha2::Sha256::digest(data);
            SmallVec::from_slice(&sha2::Sha256::digest(once)[..])
        }
    }
}

/// Reconstructs the scriptCode: the bytes from the last executed
/// `OP_CODESEPARATOR` (or the whole script) through the end.
fn script_code(codeseparator_pos: u32, instruction_start: usize, script: &[u8]) -> Vec<u8> {
    if codeseparator_pos == CODESEPARATOR_POSITION {
        return script.to_vec();
    }
    let start = usize::try_from(codeseparator_pos).unwrap_or(0);
    if start >= script.len() || start > instruction_start {
        return script.to_vec();
    }
    script.get(start..).unwrap_or_default().to_vec()
}

/// Removes every byte-identical occurrence of `needle` from `haystack`,
/// returning the cleaned script and the number of removals.
fn remove_all(haystack: &[u8], needle: &[u8]) -> (Vec<u8>, usize) {
    if needle.is_empty() {
        return (haystack.to_vec(), 0);
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut removed = 0_usize;
    let mut cursor = haystack;
    while !cursor.is_empty() {
        let consumed = instruction_len(cursor);
        let (instr, rest) = cursor.split_at(consumed);
        if instr == needle {
            removed += 1;
        } else {
            out.extend_from_slice(instr);
        }
        cursor = rest;
    }
    (out, removed)
}

/// Returns the total byte length of the instruction at the head of `script`.
fn instruction_len(script: &[u8]) -> usize {
    let Some(&op) = script.first() else {
        return 0;
    };
    let (header, payload) = if (0x01..=0x4b).contains(&op) {
        (1_usize, usize::from(op))
    } else {
        match op {
            opcode::OP_PUSHDATA1 => {
                let len = usize::from(script.get(1).copied().unwrap_or(0));
                (2, len)
            }
            opcode::OP_PUSHDATA2 => {
                let len = u16::from_le_bytes([
                    script.get(1).copied().unwrap_or(0),
                    script.get(2).copied().unwrap_or(0),
                ]);
                (3, usize::from(len))
            }
            opcode::OP_PUSHDATA4 => {
                let bytes = [
                    script.get(1).copied().unwrap_or(0),
                    script.get(2).copied().unwrap_or(0),
                    script.get(3).copied().unwrap_or(0),
                    script.get(4).copied().unwrap_or(0),
                ];
                // u32 always fits in usize (>= 32 bits) on supported targets.
                let wide = u64::from(u32::from_le_bytes(bytes));
                let len = usize::try_from(wide).unwrap_or(usize::MAX);
                (5, len)
            }
            _ => (1, 0),
        }
    };
    header.saturating_add(payload).min(script.len())
}

/// Core's `EvalChecksig`: dispatches to pre-tapscript (ECDSA) or tapscript
/// (Schnorr) handling, returning whether the signature check succeeded.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors Core's EvalChecksig parameter list over shared state"
)]
fn eval_checksig(
    sig: &[u8],
    pubkey: &[u8],
    instruction_start: usize,
    codeseparator_pos: u32,
    script: &[u8],
    flags: VerifyFlags,
    checker: &mut TxSignatureChecker<'_>,
    sigversion: SigVersion,
    validation_weight_left: &mut Option<i64>,
    tapleaf_hash: Option<&Hash256>,
) -> Result<bool, ScriptError> {
    match sigversion {
        SigVersion::Base | SigVersion::WitnessV0 => {
            let mut code = script_code(codeseparator_pos, instruction_start, script);
            if sigversion == SigVersion::Base {
                let needle = push_data(sig);
                let (cleaned, found) = remove_all(&code, &needle);
                code = cleaned;
                if found > 0 && flags.contains(VerifyFlags::CONST_SCRIPTCODE) {
                    return Err(ScriptError::Invalid {
                        code: ScriptErrCode::SigFindAndDelete,
                    });
                }
            }
            let success = checker.check_ecdsa_signature(sig, pubkey, &code, sigversion, flags)?;
            if !success && flags.contains(VerifyFlags::NULLFAIL) && !sig.is_empty() {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::SigNullFail,
                });
            }
            Ok(success)
        }
        SigVersion::Tapscript => {
            let mut success = !sig.is_empty();
            if success {
                if let Some(left) = validation_weight_left.as_mut() {
                    *left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
                    if *left < 0 {
                        return Err(ScriptError::Invalid {
                            code: ScriptErrCode::TapscriptValidationWeight,
                        });
                    }
                }
            }
            if pubkey.is_empty() {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::TapscriptEmptyPubkey,
                });
            }
            if pubkey.len() == 32 {
                if success {
                    success = checker.check_schnorr_signature(
                        sig,
                        pubkey,
                        sigversion,
                        tapleaf_hash,
                        codeseparator_pos,
                    )?;
                }
            } else if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_PUBKEYTYPE) {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::DiscourageUpgradablePubkeyType,
                });
            }
            Ok(success)
        }
        SigVersion::Taproot => Ok(false),
    }
}

/// Core's `OP_CHECKMULTISIG` handling, including the BIP147 dummy-element
/// checks and pre-segwit `FindAndDelete` over the script code.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors Core's CHECKMULTISIG parameter list over shared state"
)]
#[expect(
    clippy::too_many_lines,
    reason = "multisig check mirrors Core's CheckMultisig linear flow"
)]
fn check_multisig(
    stack: &mut Stack,
    require_minimal: bool,
    flags: VerifyFlags,
    checker: &mut TxSignatureChecker<'_>,
    sigversion: SigVersion,
    op_count: &mut usize,
    codeseparator_pos: u32,
    instruction_start: usize,
    script: &[u8],
    verify_only: bool,
) -> Result<(), ScriptError> {
    let invalid_stack = || ScriptError::Invalid {
        code: ScriptErrCode::InvalidStackOperation,
    };
    if stack.is_empty() {
        return Err(invalid_stack());
    }
    let n_keys = script_num(
        &item_bytes(stack.peek().map_err(|_| invalid_stack())?),
        require_minimal,
        4,
    )?;
    if n_keys < 0 {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::PubkeyCount,
        });
    }
    let keys = usize::try_from(n_keys).map_err(|_| ScriptError::Invalid {
        code: ScriptErrCode::PubkeyCount,
    })?;
    if keys > MAX_PUBKEYS_PER_MULTISIG {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::PubkeyCount,
        });
    }
    *op_count += keys;
    if *op_count > MAX_OPS_PER_SCRIPT {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::OpCount,
        });
    }
    if stack.len() < keys + 2 {
        return Err(invalid_stack());
    }
    let n_sigs = script_num(
        &item_bytes(stack.peek_at(keys + 1).map_err(|_| invalid_stack())?),
        require_minimal,
        4,
    )?;
    if n_sigs < 0 || n_sigs > n_keys {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::SigCount,
        });
    }
    let sigs = usize::try_from(n_sigs).map_err(|_| ScriptError::Invalid {
        code: ScriptErrCode::SigCount,
    })?;
    if stack.len() < keys + sigs + 3 {
        return Err(invalid_stack());
    }

    let mut code = script_code(codeseparator_pos, instruction_start, script);
    if sigversion == SigVersion::Base {
        for index in 0..sigs {
            let sig_item = stack
                .peek_at(keys + 2 + index)
                .map_err(|_| invalid_stack())?;
            let sig = item_bytes(sig_item).into_owned();
            let needle = push_data(&sig);
            let (cleaned, found) = remove_all(&code, &needle);
            code = cleaned;
            if found > 0 && flags.contains(VerifyFlags::CONST_SCRIPTCODE) {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::SigFindAndDelete,
                });
            }
        }
    }

    let mut success = true;
    let mut keys_left = keys;
    let mut sigs_left = sigs;
    let mut key_depth = 1;
    let mut sig_depth = keys + 2;
    while success && sigs_left > 0 {
        let sig_item = stack.peek_at(sig_depth).map_err(|_| invalid_stack())?;
        let key_item = stack.peek_at(key_depth).map_err(|_| invalid_stack())?;
        let sig = item_bytes(sig_item).into_owned();
        let pubkey = item_bytes(key_item).into_owned();
        let ok = checker.check_ecdsa_signature(&sig, &pubkey, &code, sigversion, flags)?;
        if ok {
            sig_depth += 1;
            sigs_left -= 1;
        }
        key_depth += 1;
        keys_left -= 1;
        if sigs_left > keys_left {
            success = false;
        }
    }

    // Clean up the actual arguments (keys + sigs + the two counts).
    let mut args = keys + sigs + 2;
    let mut key_scan = keys + 2;
    while args > 0 {
        if !success && flags.contains(VerifyFlags::NULLFAIL) && key_scan == 0 {
            let top = stack.peek().map_err(|_| invalid_stack())?;
            if !item_bytes(top).is_empty() {
                return Err(ScriptError::Invalid {
                    code: ScriptErrCode::SigNullFail,
                });
            }
        }
        key_scan = key_scan.saturating_sub(1);
        stack.pop().map_err(|_| invalid_stack())?;
        args -= 1;
    }

    // The dummy element is consumed without inspection.
    if stack.is_empty() {
        return Err(invalid_stack());
    }
    if flags.contains(VerifyFlags::NULLDUMMY)
        && !item_bytes(stack.peek().map_err(|_| invalid_stack())?).is_empty()
    {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::SigNullDummy,
        });
    }
    stack.pop().map_err(|_| invalid_stack())?;

    push_bytes(stack, if success { &[1] } else { &[] })?;
    if verify_only {
        if success {
            stack.pop().map_err(|_| invalid_stack())?;
        } else {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::CheckMultisigVerify,
            });
        }
    }
    Ok(())
}
