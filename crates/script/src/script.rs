//! Native script parsing, classification, and building helpers.
//!
//! Byte-level replacements for the `bitcoin::Script` utilities the workspace
//! consumed before the native-primitives migration. Semantics are bug-for-bug
//! with rust-bitcoin 0.32's `Script` helpers (and Core's `GetOp` loop behind
//! them); differential tests pin the parity where the two overlap.

/// Opcode byte constants the workspace builds and inspects scripts with.
pub mod opcode {
    macro_rules! opcodes {
        ($($name:ident = $value:literal,)*) => {
            $(
                #[doc = concat!("`", stringify!($name), "` (", stringify!($value), ").")]
                pub const $name: u8 = $value;
            )*
        };
    }

    opcodes! {
        OP_0 = 0x00,
        OP_PUSHDATA1 = 0x4c,
        OP_PUSHDATA2 = 0x4d,
        OP_PUSHDATA4 = 0x4e,
        OP_1NEGATE = 0x4f,
        OP_PUSHNUM_1 = 0x51,
        OP_PUSHNUM_16 = 0x60,
        OP_NOP = 0x61,
        OP_IF = 0x63,
        OP_NOTIF = 0x64,
        OP_ELSE = 0x67,
        OP_ENDIF = 0x68,
        OP_VERIFY = 0x69,
        OP_RETURN = 0x6a,
        OP_TOALTSTACK = 0x6b,
        OP_FROMALTSTACK = 0x6c,
        OP_2DROP = 0x6d,
        OP_2DUP = 0x6e,
        OP_3DUP = 0x6f,
        OP_2OVER = 0x70,
        OP_2ROT = 0x71,
        OP_2SWAP = 0x72,
        OP_IFDUP = 0x73,
        OP_DEPTH = 0x74,
        OP_DROP = 0x75,
        OP_DUP = 0x76,
        OP_NIP = 0x77,
        OP_OVER = 0x78,
        OP_PICK = 0x79,
        OP_ROLL = 0x7a,
        OP_ROT = 0x7b,
        OP_SWAP = 0x7c,
        OP_TUCK = 0x7d,
        OP_SIZE = 0x82,
        OP_EQUAL = 0x87,
        OP_EQUALVERIFY = 0x88,
        OP_1ADD = 0x8b,
        OP_1SUB = 0x8c,
        OP_NEGATE = 0x8f,
        OP_ABS = 0x90,
        OP_NOT = 0x91,
        OP_0NOTEQUAL = 0x92,
        OP_ADD = 0x93,
        OP_SUB = 0x94,
        OP_BOOLAND = 0x9a,
        OP_BOOLOR = 0x9b,
        OP_NUMEQUAL = 0x9c,
        OP_NUMEQUALVERIFY = 0x9d,
        OP_NUMNOTEQUAL = 0x9e,
        OP_LESSTHAN = 0x9f,
        OP_GREATERTHAN = 0xa0,
        OP_LESSTHANOREQUAL = 0xa1,
        OP_GREATERTHANOREQUAL = 0xa2,
        OP_MIN = 0xa3,
        OP_MAX = 0xa4,
        OP_WITHIN = 0xa5,
        OP_RIPEMD160 = 0xa6,
        OP_SHA1 = 0xa7,
        OP_SHA256 = 0xa8,
        OP_HASH160 = 0xa9,
        OP_HASH256 = 0xaa,
        OP_CODESEPARATOR = 0xab,
        OP_CHECKSIG = 0xac,
        OP_CHECKSIGVERIFY = 0xad,
        OP_CHECKMULTISIG = 0xae,
        OP_CHECKMULTISIGVERIFY = 0xaf,
        OP_NOP1 = 0xb0,
        OP_CHECKLOCKTIMEVERIFY = 0xb1,
        OP_CHECKSEQUENCEVERIFY = 0xb2,
        OP_NOP4 = 0xb3,
        OP_NOP5 = 0xb4,
        OP_NOP6 = 0xb5,
        OP_NOP7 = 0xb6,
        OP_NOP8 = 0xb7,
        OP_NOP9 = 0xb8,
        OP_NOP10 = 0xb9,
        OP_CHECKSIGADD = 0xba,
    }

    /// Returns the small-integer value an `OP_PUSHNUM_*` opcode encodes,
    /// or `None` for every other opcode.
    #[must_use]
    pub const fn decode_pushnum(opcode: u8) -> Option<u8> {
        if opcode >= OP_PUSHNUM_1 && opcode <= OP_PUSHNUM_16 {
            Some(opcode - OP_PUSHNUM_1 + 1)
        } else {
            None
        }
    }
}

/// One parsed script instruction: an opcode or a data push.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instruction<'a> {
    /// Any non-push opcode byte.
    Op(u8),
    /// The byte slice pushed by a direct push, `OP_PUSHDATA1/2/4`, or `OP_0`.
    PushBytes(&'a [u8]),
}

/// A push length or payload runs past the end of the script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EarlyEndOfScript;

/// Iterator over the instructions of a script, yielding a parse error at the
/// first malformed push (and never again, matching Core's `GetOp` loop).
///
/// Byte semantics mirror rust-bitcoin's non-minimal `Script::instructions`:
/// `0x01..=0x4b` are direct pushes, `OP_PUSHDATA1/2/4` carry an explicit
/// little-endian length, `0x00` pushes an empty slice, and every other byte
/// is an [`Instruction::Op`].
#[derive(Clone, Debug)]
pub struct Instructions<'a> {
    remaining: &'a [u8],
    failed: bool,
}

/// Iterates the instructions of `script`.
#[must_use]
pub const fn instructions(script: &[u8]) -> Instructions<'_> {
    Instructions {
        remaining: script,
        failed: false,
    }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = Result<Instruction<'a>, EarlyEndOfScript>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let (&opcode, rest) = self.remaining.split_first()?;
        match opcode {
            0x01..=0x4b => Some(
                self.take_slice(usize::from(opcode), rest)
                    .map(Instruction::PushBytes),
            ),
            opcode::OP_PUSHDATA1 => {
                let len = self.read_len_le(1);
                let len = usize::try_from(len).unwrap_or(usize::MAX);
                Some(
                    self.take_len_slice(len, 1, rest)
                        .map(Instruction::PushBytes),
                )
            }
            opcode::OP_PUSHDATA2 => {
                let len = self.read_len_le(2);
                let len = usize::try_from(len).unwrap_or(usize::MAX);
                Some(
                    self.take_len_slice(len, 2, rest)
                        .map(Instruction::PushBytes),
                )
            }
            opcode::OP_PUSHDATA4 => {
                let len = self.read_len_le(4);
                let len = usize::try_from(len).unwrap_or(usize::MAX);
                Some(
                    self.take_len_slice(len, 4, rest)
                        .map(Instruction::PushBytes),
                )
            }
            _ => {
                self.remaining = rest;
                if opcode == opcode::OP_0 {
                    Some(Ok(Instruction::PushBytes(&[])))
                } else {
                    Some(Ok(Instruction::Op(opcode)))
                }
            }
        }
    }
}

impl<'a> Instructions<'a> {
    /// Consumes `len` bytes from `rest`, failing the iterator on truncation.
    fn take_slice(&mut self, len: usize, rest: &'a [u8]) -> Result<&'a [u8], EarlyEndOfScript> {
        if let Some(data) = rest.get(..len) {
            self.remaining = &rest[len..];
            Ok(data)
        } else {
            self.failed = true;
            Err(EarlyEndOfScript)
        }
    }

    /// Reads a little-endian push length of `len_bytes` width starting one byte
    /// into `self.remaining`; `u64::MAX` marks truncation.
    fn read_len_le(&mut self, len_bytes: usize) -> u64 {
        if self.remaining.len() < 1 + len_bytes {
            self.failed = true;
            return u64::MAX;
        }
        let mut value = 0_u64;
        for (index, byte) in self.remaining[1..=len_bytes].iter().enumerate() {
            value |= u64::from(*byte) << (8 * index);
        }
        value
    }

    /// Completes a length-prefixed push whose payload starts `start` bytes into
    /// the original `rest` slice.
    fn take_len_slice(
        &mut self,
        len: usize,
        start: usize,
        rest: &'a [u8],
    ) -> Result<&'a [u8], EarlyEndOfScript> {
        if let Some(payload) = rest.get(start..) {
            self.take_slice(len, payload)
        } else {
            self.failed = true;
            Err(EarlyEndOfScript)
        }
    }
}

/// Returns the total byte length of the instruction at the head of `script`.
pub(crate) fn instruction_len(script: &[u8]) -> usize {
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

/// Returns `true` when every instruction of `script` is a push.
///
/// Small-integer pushnum opcodes count as pushes. This mirrors Core's
/// `IsPushOnly` as rust-bitcoin implements it: parse failure or any opcode
/// above `OP_16` fails.
#[must_use]
pub fn is_push_only(script: &[u8]) -> bool {
    instructions(script).all(|instruction| match instruction {
        Ok(Instruction::PushBytes(_)) => true,
        Ok(Instruction::Op(op)) => op <= opcode::OP_PUSHNUM_16,
        Err(EarlyEndOfScript) => false,
    })
}

/// Returns `true` when the script starts with `OP_RETURN`.
#[must_use]
pub fn is_op_return(script: &[u8]) -> bool {
    script.first() == Some(&opcode::OP_RETURN)
}

/// Returns `true` for `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`.
#[must_use]
pub fn is_p2pkh(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == opcode::OP_DUP
        && script[1] == opcode::OP_HASH160
        && script[2] == 0x14
        && script[23] == opcode::OP_EQUALVERIFY
        && script[24] == opcode::OP_CHECKSIG
}

/// Returns `true` for `OP_HASH160 <20 bytes> OP_EQUAL`.
#[must_use]
pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == opcode::OP_HASH160
        && script[1] == 0x14
        && script[22] == opcode::OP_EQUAL
}

/// Returns the public-key bytes of a bare P2PK script
/// (`<33 or 65 bytes> OP_CHECKSIG`), or `None` for any other shape.
///
/// The push must decode as a `CPubKey` (`ValidSize`: 33-byte keys start
/// `0x02`/`0x03`, 65-byte keys `0x04`/`0x06`/`0x07`), the strictness Core's
/// `Solver` applies before classifying `pubkey`.
#[must_use]
pub fn p2pk_pubkey_bytes(script: &[u8]) -> Option<&[u8]> {
    let key = match script.len() {
        67 if script[0] == 0x41 && script[66] == opcode::OP_CHECKSIG => &script[1..66],
        35 if script[0] == 0x21 && script[34] == opcode::OP_CHECKSIG => &script[1..34],
        _ => return None,
    };
    match key.len() {
        33 if matches!(key[0], 0x02 | 0x03) => Some(key),
        65 if matches!(key[0], 0x04 | 0x06 | 0x07) => Some(key),
        _ => None,
    }
}

/// Returns `true` for a bare P2PK script.
#[must_use]
pub fn is_p2pk(script: &[u8]) -> bool {
    p2pk_pubkey_bytes(script).is_some()
}

/// Returns `true` for a v0 witness program: `OP_0 <20 bytes>`.
#[must_use]
pub fn is_p2wpkh(script: &[u8]) -> bool {
    script.len() == 22 && script[0] == opcode::OP_0 && script[1] == 0x14
}

/// Returns `true` for `OP_0 <32 bytes>`.
#[must_use]
pub fn is_p2wsh(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == opcode::OP_0 && script[1] == 0x20
}

/// Returns `true` for a taproot output: `OP_1 <32 bytes>`.
#[must_use]
pub fn is_p2tr(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == opcode::OP_PUSHNUM_1 && script[1] == 0x20
}

/// Returns `true` for `OP_1 OP_PUSHBYTES_2 0x4e73` (pay-to-anchor).
#[must_use]
pub fn is_p2a(script: &[u8]) -> bool {
    script == [0x51, 0x02, 0x4e, 0x73]
}

/// Returns the witness version and program of a segwit output script, or
/// `None` when the script is not a well-formed witness program.
#[must_use]
pub fn witness_program(script: &[u8]) -> Option<(u8, &[u8])> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }
    let version_byte = script[0];
    let program_len = usize::from(script[1]);
    let version = if version_byte == opcode::OP_0 {
        0
    } else {
        opcode::decode_pushnum(version_byte)?
    };
    if !(2..=40).contains(&program_len) || script.len() - 2 != program_len {
        return None;
    }
    Some((version, &script[2..]))
}

/// Returns `true` when the script is a witness program of any version.
#[must_use]
pub fn is_witness_program(script: &[u8]) -> bool {
    witness_program(script).is_some()
}

/// Returns `true` for a bare multisig script.
///
/// Shape: `OP_m <n key pushes> OP_n OP_CHECKMULTISIG` with `m <= n`, mirroring
/// rust-bitcoin's `Script::is_multisig`. Key-length checking is the caller's
/// policy decision, not a script-shape property.
#[must_use]
pub fn is_multisig(script: &[u8]) -> bool {
    let mut iter = instructions(script);
    let required_sigs = match iter.next() {
        Some(Ok(Instruction::Op(op))) => match opcode::decode_pushnum(op) {
            Some(pushnum) => pushnum,
            None => return false,
        },
        _ => return false,
    };

    let mut num_pubkeys: u8 = 0;
    while let Some(Ok(instruction)) = iter.next() {
        match instruction {
            Instruction::PushBytes(_) => num_pubkeys = num_pubkeys.saturating_add(1),
            Instruction::Op(op) => {
                // The opcode after the key pushes must be the OP_n key count;
                // any other opcode makes the script malformed, not multisig.
                match opcode::decode_pushnum(op) {
                    Some(pushnum) if pushnum == num_pubkeys => {}
                    _ => return false,
                }
                break;
            }
        }
    }

    if required_sigs > num_pubkeys {
        return false;
    }
    match iter.next() {
        Some(Ok(Instruction::Op(op))) if op == opcode::OP_CHECKMULTISIG => {}
        _ => return false,
    }
    iter.next().is_none()
}

/// Counts the pubkeys in a bare multisig script, or `None` unless it matches
/// Core's `MatchMultisig` exactly.
///
/// `m` and `n` are small integers in `1..=MAX_PUBKEYS_PER_MULTISIG` encoded as
/// `OP_1..=OP_16` or minimally encoded script-number pushes, every key push
/// decodes as a `CPubKey` (33 bytes starting `0x02`/`0x03`, 65 bytes starting
/// `0x04`/`0x06`/`0x07`), `m <= n` equals the number of key pushes, and
/// `OP_CHECKMULTISIG` ends the script.
/// Core `MAX_PUBKEYS_PER_MULTISIG`.
const MAX_BARE_MULTISIG_PUBKEYS: i64 = 20;

/// Yields the next element as Core's `CScript::GetOp` does: the opcode
/// byte and its pushed data (empty for non-push opcodes).
fn next_op<'a>(script: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    let &opcode = script.get(*pos)?;
    *pos += 1;
    let len = match opcode {
        0x01..=0x4b => usize::from(opcode),
        opcode::OP_PUSHDATA1 | opcode::OP_PUSHDATA2 | opcode::OP_PUSHDATA4 => {
            let width = if opcode == opcode::OP_PUSHDATA4 {
                4
            } else {
                usize::from(opcode - opcode::OP_PUSHDATA1 + 1)
            };
            let bytes = script.get(*pos..pos.checked_add(width)?)?;
            *pos += width;
            let mut len = 0usize;
            for (shift, byte) in bytes.iter().enumerate() {
                len |= usize::from(*byte) << (8 * shift);
            }
            len
        }
        _ => 0,
    };
    let data = script.get(*pos..pos.checked_add(len)?)?;
    *pos += len;
    Some((opcode, data))
}

/// Core `CheckMinimalPush`: the opcode must be the smallest push form
/// that can carry `data`, and one-byte small integers must use their
/// dedicated opcodes (`OP_0`, `OP_1NEGATE`, `OP_1..=OP_16`).
fn minimal_push(opcode: u8, data: &[u8]) -> bool {
    match data.len() {
        0 => opcode == opcode::OP_0,
        1 if (1..=16).contains(&data[0]) || data[0] == 0x81 => false,
        1..=75 => usize::from(opcode) == data.len(),
        76..=255 => opcode == opcode::OP_PUSHDATA1,
        256..=65_535 => opcode == opcode::OP_PUSHDATA2,
        _ => true,
    }
}

/// Core `CScriptNum` with `fRequireMinimal`: the sign-magnitude value of
/// a little-endian byte string of at most 4 bytes.
fn minimal_script_num(data: &[u8]) -> Option<i64> {
    if data.is_empty() {
        return Some(0);
    }
    if data.len() > 4 {
        return None;
    }
    let last = *data.last()?;
    if last.trailing_zeros() >= 7 && (data.len() == 1 || data[data.len() - 2] & 0x80 == 0) {
        return None;
    }
    let mut value = 0i64;
    for (shift, byte) in data.iter().enumerate() {
        let bits = if shift == data.len() - 1 {
            i64::from(*byte & 0x7f)
        } else {
            i64::from(*byte)
        };
        value |= bits << (8 * shift);
    }
    Some(if last & 0x80 != 0 { -value } else { value })
}

/// Core `GetScriptNumber`: a minimally encoded count in `min..=max`,
/// whether carried by an `OP_n` opcode or a data push.
fn script_count(opcode: u8, data: &[u8], min: i64, max: i64) -> Option<u8> {
    let count = if let Some(pushnum) = opcode::decode_pushnum(opcode) {
        i64::from(pushnum)
    } else if opcode <= opcode::OP_PUSHDATA4 {
        if !minimal_push(opcode, data) {
            return None;
        }
        minimal_script_num(data)?
    } else {
        return None;
    };
    if count < min || count > max {
        return None;
    }
    u8::try_from(count).ok()
}

/// Core `CPubKey::ValidSize`.
fn pubkey_valid_size(data: &[u8]) -> bool {
    match data.len() {
        33 => matches!(data[0], 0x02 | 0x03),
        65 => matches!(data[0], 0x04 | 0x06 | 0x07),
        _ => false,
    }
}

/// Counts the pubkeys in a bare multisig script, or `None` unless it matches
/// Core's `MatchMultisig` exactly.
///
/// `m` and `n` are small integers in `1..=MAX_PUBKEYS_PER_MULTISIG` encoded as
/// `OP_1..=OP_16` or minimally encoded script-number pushes, every key push
/// decodes as a `CPubKey` (33 bytes starting `0x02`/`0x03`, 65 bytes starting
/// `0x04`/`0x06`/`0x07`), `m <= n` equals the number of key pushes, and
/// `OP_CHECKMULTISIG` ends the script.
#[must_use]
pub fn multisig_key_count(script: &[u8]) -> Option<u8> {
    if *script.last()? != opcode::OP_CHECKMULTISIG {
        return None;
    }
    let mut pos = 0usize;
    let (op, data) = next_op(script, &mut pos)?;
    let required = i64::from(script_count(op, data, 1, MAX_BARE_MULTISIG_PUBKEYS)?);
    let mut keys = 0usize;
    let (op, data) = loop {
        let (op, data) = next_op(script, &mut pos)?;
        if !pubkey_valid_size(data) {
            break (op, data);
        }
        keys = keys.checked_add(1)?;
    };
    let declared = script_count(op, data, required, MAX_BARE_MULTISIG_PUBKEYS)?;
    if usize::from(declared) != keys {
        return None;
    }
    if script.get(pos) != Some(&opcode::OP_CHECKMULTISIG) || pos + 1 != script.len() {
        return None;
    }
    Some(declared)
}

/// Returns the smallest non-dust value in satoshis for an output paying
/// `script` under `dust_relay_fee_sat_per_kvb`.
///
/// Mirrors Core's `GetDustThreshold` as rust-bitcoin's
/// `minimal_non_dust_custom` implements it (spend overhead copied from Core;
/// division by 1000 at the end only).
#[must_use]
pub fn minimal_non_dust(script: &[u8], dust_relay_fee_sat_per_kvb: u64) -> u64 {
    // Scripts over the consensus execution limit are unspendable, as in Core.
    if script.len() > 10_000 {
        return 0;
    }
    let script_size = varint_size(script.len()).saturating_add(script.len());
    let size = if is_op_return(script) {
        0
    } else if is_witness_program(script) {
        32 + 4 + 1 + (107 / 4) + 4 + 8 + script_size
    } else {
        32 + 4 + 1 + 107 + 4 + 8 + script_size
    };
    let product =
        dust_relay_fee_sat_per_kvb.saturating_mul(u64::try_from(size).unwrap_or(u64::MAX));
    product.saturating_add(999) / 1000
}

/// Encodes `data` as a minimal canonical push (direct push for 1..=75 bytes,
/// `OP_PUSHDATA1/2/4` above that).
#[must_use]
pub fn push_data(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut out = Vec::with_capacity(len + 5);
    if len < 76 {
        let len8 = u8::try_from(len).unwrap_or_else(|_| unreachable!("len < 76 fits u8"));
        out.push(len8);
    } else if u8::try_from(len).is_ok() {
        out.push(opcode::OP_PUSHDATA1);
        let len8 = u8::try_from(len).unwrap_or_else(|_| unreachable!("len <= 255 fits u8"));
        out.push(len8);
    } else if u16::try_from(len).is_ok() {
        out.push(opcode::OP_PUSHDATA2);
        let len16 = u16::try_from(len).unwrap_or_else(|_| unreachable!("len <= 65535 fits u16"));
        out.extend_from_slice(&len16.to_le_bytes());
    } else {
        out.push(opcode::OP_PUSHDATA4);
        let len32 = u32::try_from(len).unwrap_or_else(|_| {
            unreachable!("a slice longer than 2^32 bytes is not a script push");
        });
        out.extend_from_slice(&len32.to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

/// Encodes an integer as a minimal script push.
///
/// This is Core's `CScript::operator<<(CScriptNum)`: values -1..=16 use the
/// dedicated pushnum opcodes, everything else a sign-minimal
/// two's-complement-magnitude data push.
#[must_use]
pub fn push_int(value: i64) -> Vec<u8> {
    match value {
        0 => return vec![opcode::OP_0],
        -1 => return vec![opcode::OP_1NEGATE],
        1..=16 => {
            let small = u8::try_from(value).unwrap_or_else(|_| unreachable!("value is 1..=16"));
            return vec![opcode::OP_PUSHNUM_1 + (small - 1)];
        }
        _ => {}
    }
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut bytes = Vec::new();
    while magnitude > 0 {
        bytes.push(magnitude.to_le_bytes()[0]);
        magnitude >>= 8;
    }
    match bytes.last_mut() {
        Some(last) if *last & 0x80 != 0 => bytes.push(if negative { 0x80 } else { 0x00 }),
        Some(last) if negative => *last |= 0x80,
        _ => {}
    }
    push_data(&bytes)
}

/// Compact-size (Bitcoin varint) encoding length in bytes.
const fn varint_size(value: usize) -> usize {
    if value < 0xfd {
        1
    } else if value <= 0xffff {
        3
    } else if value <= 0xffff_ffff {
        5
    } else {
        9
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EarlyEndOfScript, Instruction, instructions, is_multisig, is_op_return, is_p2a, is_p2pk,
        is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh, is_push_only, is_witness_program,
        minimal_non_dust, multisig_key_count, opcode, push_data, push_int,
    };

    const fn pushnum(n: u8) -> u8 {
        opcode::OP_PUSHNUM_1 + (n - 1)
    }

    #[test]
    fn pushes_round_trip_through_the_iterator() {
        let script = [
            vec![opcode::OP_0],
            push_data(&[]),
            push_data(&[0xab; 75]),
            push_data(&[0xcd; 76]),
            push_data(&[0xef; 300]),
            vec![opcode::OP_1NEGATE, opcode::OP_PUSHNUM_16, 0xff],
        ]
        .concat();
        let parsed: Vec<_> = instructions(&script)
            .map(|instruction| {
                instruction.unwrap_or_else(|error| panic!("script is well formed: {error:?}"))
            })
            .collect();
        assert_eq!(
            parsed,
            vec![
                Instruction::PushBytes(&[]),
                Instruction::PushBytes(&[]),
                Instruction::PushBytes(&[0xab; 75]),
                Instruction::PushBytes(&[0xcd; 76]),
                Instruction::PushBytes(&[0xef; 300]),
                Instruction::Op(opcode::OP_1NEGATE),
                Instruction::Op(opcode::OP_PUSHNUM_16),
                Instruction::Op(0xff),
            ]
        );
    }

    #[test]
    fn truncated_push_reports_error_once() {
        let script = [push_data(&[1, 2, 3])[..2].to_vec(), vec![opcode::OP_DUP]].concat();
        let parsed: Vec<_> = instructions(&script).collect();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], Err(EarlyEndOfScript));
    }

    #[test]
    fn push_only_rejects_non_push_opcodes_and_parse_errors() {
        let mut ok = push_data(&[1]);
        ok.push(opcode::OP_PUSHNUM_1);
        assert!(is_push_only(&ok));
        assert!(!is_push_only(&[opcode::OP_DUP]));
        assert!(!is_push_only(&[0x51, 0x20, 0x00])); // truncated 32-byte push
        assert!(!is_push_only(&[0x51, 0xff]));
    }

    #[test]
    fn output_classifiers_match_canonical_shapes() {
        let p2pkh: Vec<u8> = [vec![0x76, 0xa9, 0x14], vec![7; 20], vec![0x88, 0xac]].concat();
        assert!(is_p2pkh(&p2pkh));
        let p2sh: Vec<u8> = [vec![0xa9, 0x14], vec![7; 20], vec![0x87]].concat();
        assert!(is_p2sh(&p2sh));
        assert!(is_p2pk(
            &[vec![0x21], vec![0x02; 33], vec![opcode::OP_CHECKSIG]].concat()
        ));
        assert!(!is_p2pk(
            &[vec![0x21], vec![0x09; 33], vec![opcode::OP_CHECKSIG]].concat()
        ));
        assert!(!is_p2pk(
            &[vec![0x20], vec![9; 32], vec![opcode::OP_CHECKSIG]].concat()
        ));
        assert!(is_p2wpkh(&[vec![0x00, 0x14], vec![7; 20]].concat()));
        assert!(is_p2wsh(&[vec![0x00, 0x20], vec![7; 32]].concat()));
        assert!(is_p2tr(&[vec![0x51, 0x20], vec![7; 32]].concat()));
        assert!(is_p2a(&[0x51, 0x02, 0x4e, 0x73]));
        assert!(is_op_return(&[opcode::OP_RETURN, opcode::OP_0]));
        assert!(is_witness_program(
            &[vec![0x60, 0x28], vec![7; 40]].concat()
        ));
        assert!(!is_witness_program(
            &[vec![0x60, 0x29], vec![7; 40]].concat()
        ));
    }

    #[test]
    fn multisig_requires_matching_counts_and_trailer() {
        let ok: Vec<u8> = [
            vec![pushnum(2)],
            push_data(&[1; 33]),
            push_data(&[2; 33]),
            vec![pushnum(2), opcode::OP_CHECKMULTISIG],
        ]
        .concat();
        assert!(is_multisig(&ok));

        let count_mismatch: Vec<u8> = [
            vec![pushnum(2)],
            push_data(&[1; 33]),
            vec![opcode::OP_PUSHNUM_1, opcode::OP_CHECKMULTISIG],
        ]
        .concat();
        assert!(!is_multisig(&count_mismatch));

        let missing_trailer: Vec<u8> = [
            vec![opcode::OP_PUSHNUM_1],
            push_data(&[1; 33]),
            vec![opcode::OP_PUSHNUM_1],
        ]
        .concat();
        assert!(!is_multisig(&missing_trailer));
    }

    #[test]
    fn multisig_key_count_matches_core_strictness() {
        let keys = vec![0x02_u8; 33];
        let two_of_two: Vec<u8> = [
            vec![pushnum(2)],
            push_data(&keys),
            push_data(&keys),
            vec![pushnum(2), opcode::OP_CHECKMULTISIG],
        ]
        .concat();
        assert_eq!(multisig_key_count(&two_of_two), Some(2));

        // A key push that is not a serialized pubkey fails the match.
        let bad_key: Vec<u8> = [
            vec![opcode::OP_PUSHNUM_1],
            push_data(&[0_u8; 4]),
            vec![opcode::OP_PUSHNUM_1, opcode::OP_CHECKMULTISIG],
        ]
        .concat();
        assert!(is_multisig(&bad_key));
        assert_eq!(multisig_key_count(&bad_key), None);

        // Counts may be minimal script-number pushes, reaching past OP_16.
        let mut seventeen_of_seventeen = vec![0x01, 0x11];
        for _ in 0..17 {
            seventeen_of_seventeen.extend(push_data(&keys));
        }
        seventeen_of_seventeen.extend([0x01, 0x11, opcode::OP_CHECKMULTISIG]);
        assert_eq!(multisig_key_count(&seventeen_of_seventeen), Some(17));

        // Twenty-one keys exceeds `MAX_PUBKEYS_PER_MULTISIG`.
        let mut twenty_one = vec![opcode::OP_PUSHNUM_1];
        for _ in 0..21 {
            twenty_one.extend(push_data(&keys));
        }
        twenty_one.extend([0x01, 0x15, opcode::OP_CHECKMULTISIG]);
        assert_eq!(multisig_key_count(&twenty_one), None);

        // Non-minimal count encodings fail: PUSHDATA1 for one byte, and a
        // redundant sign byte in the value.
        let padded_push: Vec<u8> = [
            vec![opcode::OP_PUSHDATA1, 0x01, 0x01],
            push_data(&keys),
            vec![opcode::OP_PUSHNUM_1, opcode::OP_CHECKMULTISIG],
        ]
        .concat();
        assert_eq!(multisig_key_count(&padded_push), None);
        let nonminimal_num: Vec<u8> = [
            vec![0x02, 0x01, 0x00],
            push_data(&keys),
            vec![opcode::OP_PUSHNUM_1, opcode::OP_CHECKMULTISIG],
        ]
        .concat();
        assert_eq!(multisig_key_count(&nonminimal_num), None);
    }

    #[test]
    fn dust_threshold_matches_core_arithmetic() {
        // P2PKH: witness false → 32+4+1+107+4+8 + 1 varint + 25 = 182; 3000 * 182 / 1000 = 546.
        let p2pkh: Vec<u8> = [vec![0x76, 0xa9, 0x14], vec![7; 20], vec![0x88, 0xac]].concat();
        assert_eq!(minimal_non_dust(&p2pkh, 3_000), 546);
        // P2WPKH: witness true → 32+4+1+26+4+8 + 1 + 22 = 98; 3000 * 98 / 1000 = 294.
        let p2wpkh: Vec<u8> = [vec![0x00, 0x14], vec![7; 20]].concat();
        assert_eq!(minimal_non_dust(&p2wpkh, 3_000), 294);
        // OP_RETURN: always zero.
        assert_eq!(minimal_non_dust(&[opcode::OP_RETURN], 3_000), 0);
    }

    #[test]
    fn int_and_data_pushes_use_core_minimal_forms() {
        assert_eq!(push_int(0), vec![opcode::OP_0]);
        assert_eq!(push_int(1), vec![opcode::OP_PUSHNUM_1]);
        assert_eq!(push_int(16), vec![opcode::OP_PUSHNUM_16]);
        assert_eq!(push_int(-1), vec![opcode::OP_1NEGATE]);
        assert_eq!(push_int(17), vec![0x01, 0x11]);
        assert_eq!(push_int(500), vec![0x02, 0xf4, 0x01]);
        assert_eq!(push_int(-500), vec![0x02, 0xf4, 0x81]);
        assert_eq!(push_data(&[1, 2]), vec![0x02, 1, 2]);
        assert_eq!(push_data(&[0; 76])[..2], [opcode::OP_PUSHDATA1, 76]);
    }
}
