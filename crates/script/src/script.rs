//! Native script parsing, classification, and building helpers.

pub mod opcode {

    macro_rules! opcodes {
        ($($(#[$doc:meta])* $visibility:vis $name:ident = $value:literal,)*) => {
            $(
                #[doc = concat!("`", stringify!($name), "` (", stringify!($value), ").")]
                $(#[$doc])*
                $visibility const $name: u8 = $value;
            )*
        };
    }

    opcodes! {
        pub OP_0 = 0x00,
        pub(crate) OP_PUSHDATA1 = 0x4c,
        pub(crate) OP_PUSHDATA2 = 0x4d,
        pub(crate) OP_PUSHDATA4 = 0x4e,
        pub OP_1NEGATE = 0x4f,
        pub OP_RESERVED = 0x50,
        pub OP_PUSHNUM_1 = 0x51,
        pub OP_PUSHNUM_16 = 0x60,
        pub OP_IF = 0x63,
        pub OP_ENDIF = 0x68,
        pub OP_RETURN = 0x6a,
        pub OP_DROP = 0x75,
        pub OP_DUP = 0x76,
        pub OP_EQUAL = 0x87,
        pub OP_EQUALVERIFY = 0x88,
        pub OP_HASH160 = 0xa9,
        pub OP_CHECKSIG = 0xac,
        pub(crate) OP_CHECKSIGVERIFY = 0xad,
        pub OP_CHECKMULTISIG = 0xae,
        pub(crate) OP_CHECKMULTISIGVERIFY = 0xaf,
        pub(crate) OP_NOP = 0x61,
        pub(crate) OP_NOTIF = 0x64,
        pub(crate) OP_ELSE = 0x67,
        pub(crate) OP_VERIFY = 0x69,
        pub(crate) OP_TOALTSTACK = 0x6b,
        pub(crate) OP_FROMALTSTACK = 0x6c,
        pub(crate) OP_2DROP = 0x6d,
        pub(crate) OP_2DUP = 0x6e,
        pub(crate) OP_3DUP = 0x6f,
        pub(crate) OP_2OVER = 0x70,
        pub(crate) OP_2ROT = 0x71,
        pub(crate) OP_2SWAP = 0x72,
        pub(crate) OP_IFDUP = 0x73,
        pub(crate) OP_DEPTH = 0x74,
        pub(crate) OP_NIP = 0x77,
        pub(crate) OP_OVER = 0x78,
        pub(crate) OP_PICK = 0x79,
        pub(crate) OP_ROLL = 0x7a,
        pub(crate) OP_ROT = 0x7b,
        pub(crate) OP_SWAP = 0x7c,
        pub(crate) OP_TUCK = 0x7d,
        pub(crate) OP_SIZE = 0x82,
        pub(crate) OP_1ADD = 0x8b,
        pub(crate) OP_1SUB = 0x8c,
        pub(crate) OP_NEGATE = 0x8f,
        pub(crate) OP_ABS = 0x90,
        pub(crate) OP_NOT = 0x91,
        pub(crate) OP_0NOTEQUAL = 0x92,
        pub(crate) OP_ADD = 0x93,
        pub(crate) OP_SUB = 0x94,
        pub(crate) OP_BOOLAND = 0x9a,
        pub(crate) OP_BOOLOR = 0x9b,
        pub(crate) OP_NUMEQUAL = 0x9c,
        pub(crate) OP_NUMEQUALVERIFY = 0x9d,
        pub(crate) OP_NUMNOTEQUAL = 0x9e,
        pub(crate) OP_LESSTHAN = 0x9f,
        pub(crate) OP_GREATERTHAN = 0xa0,
        pub(crate) OP_LESSTHANOREQUAL = 0xa1,
        pub(crate) OP_GREATERTHANOREQUAL = 0xa2,
        pub(crate) OP_MIN = 0xa3,
        pub(crate) OP_MAX = 0xa4,
        pub(crate) OP_WITHIN = 0xa5,
        pub(crate) OP_RIPEMD160 = 0xa6,
        pub(crate) OP_SHA1 = 0xa7,
        pub(crate) OP_SHA256 = 0xa8,
        pub(crate) OP_HASH256 = 0xaa,
        pub(crate) OP_CODESEPARATOR = 0xab,
        pub(crate) OP_NOP1 = 0xb0,
        pub(crate) OP_CHECKLOCKTIMEVERIFY = 0xb1,
        pub(crate) OP_CHECKSEQUENCEVERIFY = 0xb2,
        pub(crate) OP_NOP4 = 0xb3,
        pub(crate) OP_NOP10 = 0xb9,
        pub(crate) OP_CHECKSIGADD = 0xba,
    }

    #[must_use]
    pub(crate) const fn decode_pushnum(opcode: u8) -> Option<u8> {
        if opcode >= OP_PUSHNUM_1 && opcode <= OP_PUSHNUM_16 {
            Some(opcode - OP_PUSHNUM_1 + 1)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instruction<'a> {
    Op(u8),
    PushBytes(&'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EarlyEndOfScript;

#[derive(Clone, Debug)]
pub struct Instructions<'a> {
    pub(crate) remaining: &'a [u8],
    failed: bool,
}

#[must_use]
pub const fn instructions(script: &[u8]) -> Instructions<'_> {
    Instructions {
        remaining: script,
        failed: false,
    }
}

#[must_use]
pub fn has_valid_ops(script: &[u8]) -> bool {
    instructions(script).all(|instruction| match instruction {
        Ok(Instruction::Op(op)) => op <= opcode::OP_NOP10,
        Ok(Instruction::PushBytes(data)) => data.len() <= crate::eval::MAX_SCRIPT_ELEMENT_SIZE,
        Err(_) => false,
    })
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
    fn take_slice(&mut self, len: usize, rest: &'a [u8]) -> Result<&'a [u8], EarlyEndOfScript> {
        if let Some(data) = rest.get(..len) {
            self.remaining = &rest[len..];
            Ok(data)
        } else {
            self.failed = true;
            Err(EarlyEndOfScript)
        }
    }

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

#[must_use]
pub fn is_push_only(script: &[u8]) -> bool {
    instructions(script).all(|instruction| match instruction {
        Ok(Instruction::PushBytes(_)) => true,
        Ok(Instruction::Op(op)) => op <= opcode::OP_PUSHNUM_16,
        Err(EarlyEndOfScript) => false,
    })
}

#[must_use]
pub fn is_op_return(script: &[u8]) -> bool {
    script.first() == Some(&opcode::OP_RETURN)
}

#[must_use]
pub fn is_p2pkh(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == opcode::OP_DUP
        && script[1] == opcode::OP_HASH160
        && script[2] == 0x14
        && script[23] == opcode::OP_EQUALVERIFY
        && script[24] == opcode::OP_CHECKSIG
}

#[must_use]
pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == opcode::OP_HASH160
        && script[1] == 0x14
        && script[22] == opcode::OP_EQUAL
}

#[must_use]
fn p2pk_pubkey_bytes(script: &[u8]) -> Option<&[u8]> {
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

#[must_use]
pub fn is_p2pk(script: &[u8]) -> bool {
    p2pk_pubkey_bytes(script).is_some()
}

#[must_use]
pub fn is_p2wpkh(script: &[u8]) -> bool {
    script.len() == 22 && script[0] == opcode::OP_0 && script[1] == 0x14
}

#[must_use]
pub fn is_p2wsh(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == opcode::OP_0 && script[1] == 0x20
}

#[must_use]
pub fn is_p2tr(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == opcode::OP_PUSHNUM_1 && script[1] == 0x20
}

#[must_use]
pub fn is_p2a(script: &[u8]) -> bool {
    script == [opcode::OP_PUSHNUM_1, 0x02, 0x4e, 0x73]
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

#[must_use]
pub fn is_witness_program(script: &[u8]) -> bool {
    witness_program(script).is_some()
}

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

const MAX_BARE_MULTISIG_PUBKEYS: i64 = 20;

fn next_op<'a>(
    iter: &mut Instructions<'a>,
    script: &'a [u8],
    pos: &mut usize,
) -> Option<(u8, &'a [u8])> {
    let (op, data) = match iter.next()? {
        Ok(Instruction::PushBytes(data)) => (script[*pos], data),
        Ok(Instruction::Op(op)) => (op, &script[..0]),
        Err(_) => return None,
    };
    *pos = script.len() - iter.remaining.len();
    Some((op, data))
}

pub(crate) fn minimal_push(data: &[u8], opcode: u8) -> bool {
    match data.len() {
        0 => opcode == opcode::OP_0,
        1 if (1..=16).contains(&data[0]) || data[0] == 0x81 => false,
        1..=75 => usize::from(opcode) == data.len(),
        76..=255 => opcode == opcode::OP_PUSHDATA1,
        256..=65_535 => opcode == opcode::OP_PUSHDATA2,
        _ => true,
    }
}

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

fn script_count(opcode: u8, data: &[u8], min: i64, max: i64) -> Option<u8> {
    let count = if let Some(pushnum) = opcode::decode_pushnum(opcode) {
        i64::from(pushnum)
    } else if opcode <= opcode::OP_PUSHDATA4 {
        if !minimal_push(data, opcode) {
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

fn pubkey_valid_size(data: &[u8]) -> bool {
    match data.len() {
        33 => matches!(data[0], 0x02 | 0x03),
        65 => matches!(data[0], 0x04 | 0x06 | 0x07),
        _ => false,
    }
}

#[must_use]
pub fn multisig_key_count(script: &[u8]) -> Option<u8> {
    if *script.last()? != opcode::OP_CHECKMULTISIG {
        return None;
    }
    let mut iter = instructions(script);
    let mut pos = 0usize;
    let (op, data) = next_op(&mut iter, script, &mut pos)?;
    let required = i64::from(script_count(op, data, 1, MAX_BARE_MULTISIG_PUBKEYS)?);
    let mut keys = 0usize;
    let (op, data) = loop {
        let (op, data) = next_op(&mut iter, script, &mut pos)?;
        if !pubkey_valid_size(data) {
            break (op, data);
        }
        keys = keys.checked_add(1)?;
    };
    let declared = script_count(op, data, required, MAX_BARE_MULTISIG_PUBKEYS)?;
    if usize::from(declared) != keys {
        return None;
    }
    match iter.next() {
        Some(Ok(Instruction::Op(op)))
            if op == opcode::OP_CHECKMULTISIG && iter.remaining.is_empty() => {}
        _ => return None,
    }
    Some(declared)
}

/// Returns the smallest non-dust value in satoshis for an output paying
/// `script` under `dust_relay_fee_sat_per_kvb`.
#[must_use]
pub fn minimal_non_dust(script: &[u8], dust_relay_fee_sat_per_kvb: u64) -> u64 {
    if script.len() > 10_000 {
        return 0;
    }
    let script_size =
        bitcoin_rs_primitives::varint::encoded_len(u64::try_from(script.len()).unwrap_or(u64::MAX))
            .saturating_add(script.len());
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

#[cfg(test)]
mod tests {
    use super::{
        EarlyEndOfScript, Instruction, has_valid_ops, instructions, is_multisig, is_op_return,
        is_p2a, is_p2pk, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh, is_push_only,
        is_witness_program, minimal_non_dust, multisig_key_count, opcode, push_data, push_int,
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
        ok.push(opcode::OP_RESERVED);
        assert!(is_push_only(&ok));
        assert!(is_push_only(&[opcode::OP_RESERVED]));
        assert!(!is_push_only(&[opcode::OP_DUP]));
        assert!(!is_push_only(&[0x51, 0x20, 0x00]));
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

        let bad_key: Vec<u8> = [
            vec![opcode::OP_PUSHNUM_1],
            push_data(&[0_u8; 4]),
            vec![opcode::OP_PUSHNUM_1, opcode::OP_CHECKMULTISIG],
        ]
        .concat();
        assert!(is_multisig(&bad_key));
        assert_eq!(multisig_key_count(&bad_key), None);

        let mut seventeen_of_seventeen = vec![0x01, 0x11];
        for _ in 0..17 {
            seventeen_of_seventeen.extend(push_data(&keys));
        }
        seventeen_of_seventeen.extend([0x01, 0x11, opcode::OP_CHECKMULTISIG]);
        assert_eq!(multisig_key_count(&seventeen_of_seventeen), Some(17));

        let mut twenty_one = vec![opcode::OP_PUSHNUM_1];
        for _ in 0..21 {
            twenty_one.extend(push_data(&keys));
        }
        twenty_one.extend([0x01, 0x15, opcode::OP_CHECKMULTISIG]);
        assert_eq!(multisig_key_count(&twenty_one), None);

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
        let p2pkh: Vec<u8> = [vec![0x76, 0xa9, 0x14], vec![7; 20], vec![0x88, 0xac]].concat();
        assert_eq!(minimal_non_dust(&p2pkh, 3_000), 546);
        let p2wpkh: Vec<u8> = [vec![0x00, 0x14], vec![7; 20]].concat();
        assert_eq!(minimal_non_dust(&p2wpkh, 3_000), 294);
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

    #[test]
    fn has_valid_ops_enforces_core_legacy_boundary() {
        assert!(has_valid_ops(&[opcode::OP_NOP10]));
        assert!(has_valid_ops(&[opcode::OP_DUP, opcode::OP_NOP10]));

        assert!(!has_valid_ops(&[opcode::OP_CHECKSIGADD]));
        assert!(!has_valid_ops(&[0xba]));

        assert!(!has_valid_ops(&[0xbb]));
        assert!(!has_valid_ops(&[0xff]));

        assert!(!has_valid_ops(&[opcode::OP_PUSHDATA1]));
        assert!(!has_valid_ops(&[0x02, 0x01]));

        let max_element = vec![0x42; crate::eval::MAX_SCRIPT_ELEMENT_SIZE];
        assert!(has_valid_ops(&push_data(&max_element)));

        let over_max_element = vec![0x42; crate::eval::MAX_SCRIPT_ELEMENT_SIZE + 1];
        assert!(!has_valid_ops(&push_data(&over_max_element)));
    }
}
