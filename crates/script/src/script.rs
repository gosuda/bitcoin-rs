//! Native script parsing, classification, and building helpers.
//!
//! Byte-level replacements for the `bitcoin::Script` utilities the workspace
//! consumed before the native-primitives migration. Semantics are bug-for-bug
//! with rust-bitcoin 0.32's `Script` helpers (and Core's `GetOp` loop behind
//! them); differential tests pin the parity where the two overlap.

/// Opcode byte constants the workspace builds and inspects scripts with.
pub mod opcode {
    /// `OP_0`: pushes an empty byte string.
    pub const OP_0: u8 = 0x00;
    /// `OP_PUSHDATA1`: the next byte is the push length.
    pub const OP_PUSHDATA1: u8 = 0x4c;
    /// `OP_PUSHDATA2`: the next two little-endian bytes are the push length.
    pub const OP_PUSHDATA2: u8 = 0x4d;
    /// `OP_PUSHDATA4`: the next four little-endian bytes are the push length.
    pub const OP_PUSHDATA4: u8 = 0x4e;
    /// `OP_1NEGATE`: pushes the number -1.
    pub const OP_1NEGATE: u8 = 0x4f;
    /// `OP_1`: pushes the number 1 (`OP_PUSHNUM_1`).
    pub const OP_PUSHNUM_1: u8 = 0x51;
    /// `OP_16`: pushes the number 16 (`OP_PUSHNUM_16`).
    pub const OP_PUSHNUM_16: u8 = 0x60;
    /// `OP_RETURN`: marks an unspendable provably-prunable output.
    pub const OP_RETURN: u8 = 0x6a;
    /// `OP_DUP`: duplicates the top stack item.
    pub const OP_DUP: u8 = 0x76;
    /// `OP_EQUAL`: pushes whether the top two stack items are equal.
    pub const OP_EQUAL: u8 = 0x87;
    /// `OP_EQUALVERIFY`: `OP_EQUAL` followed by `OP_VERIFY`.
    pub const OP_EQUALVERIFY: u8 = 0x88;
    /// `OP_HASH160`: RIPEMD160(SHA256(x)).
    pub const OP_HASH160: u8 = 0xa9;
    /// `OP_CHECKSIG`: verifies a signature against the top public key.
    pub const OP_CHECKSIG: u8 = 0xac;
    /// `OP_CHECKSIGVERIFY`: `OP_CHECKSIG` followed by `OP_VERIFY`.
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    /// `OP_CHECKMULTISIG`: verifies an m-of-n multisignature set.
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    /// `OP_CHECKMULTISIGVERIFY`: `OP_CHECKMULTISIG` followed by `OP_VERIFY`.
    pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

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
#[must_use]
pub fn p2pk_pubkey_bytes(script: &[u8]) -> Option<&[u8]> {
    match script.len() {
        67 if script[0] == 0x41 && script[66] == opcode::OP_CHECKSIG => Some(&script[1..66]),
        35 if script[0] == 0x21 && script[34] == opcode::OP_CHECKSIG => Some(&script[1..34]),
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
                if let Some(pushnum) = opcode::decode_pushnum(op) {
                    if pushnum != num_pubkeys {
                        return false;
                    }
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

/// Returns the smallest non-dust value in satoshis for an output paying
/// `script` under `dust_relay_fee_sat_per_kvb`.
///
/// Mirrors Core's `GetDustThreshold` as rust-bitcoin's
/// `minimal_non_dust_custom` implements it (spend overhead copied from Core;
/// division by 1000 at the end only).
#[must_use]
pub fn minimal_non_dust(script: &[u8], dust_relay_fee_sat_per_kvb: u64) -> u64 {
    let script_size = varint_size(script.len()).saturating_add(script.len());
    let size = if is_op_return(script) {
        0
    } else if is_witness_program(script) {
        32 + 4 + 1 + (107 / 4) + 4 + 8 + script_size
    } else {
        32 + 4 + 1 + 107 + 4 + 8 + script_size
    };
    let fee = dust_relay_fee_sat_per_kvb.saturating_mul(u64::try_from(size).unwrap_or(u64::MAX));
    fee.saturating_add(999) / 1000
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
        minimal_non_dust, opcode, push_data, push_int,
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
            &[vec![0x21], vec![9; 33], vec![opcode::OP_CHECKSIG]].concat()
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
