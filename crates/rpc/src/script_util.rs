//! Byte-level script primitives used by the RPC layer.
//!
//! WHY-local: this worktree's `crates/rpc/Cargo.toml` cannot gain a
//! `bitcoin-rs-script` dependency (manifest edits are out of scope for the 2a
//! rpc migration), so the handful of classification helpers the RPC
//! projections need are mirrored here byte-for-byte from
//! `crates/script/src/script.rs`. At rebase, swap these aliases for
//! `bitcoin_rs_script::{...}` and delete this module; the functions are
//! deliberately shape-identical to make that a pure import rewrite.

/// Opcode byte constants (subset mirroring `bitcoin_rs_script::opcode`).
pub mod opcode {
    /// `OP_0`: pushes an empty byte string.
    pub const OP_0: u8 = 0x00;
    /// `OP_PUSHDATA1`: the next byte is the push length.
    pub const OP_PUSHDATA1: u8 = 0x4c;
    /// `OP_PUSHDATA2`: the next two little-endian bytes are the push length.
    pub const OP_PUSHDATA2: u8 = 0x4d;
    /// `OP_PUSHDATA4`: the next four little-endian bytes are the push length.
    pub const OP_PUSHDATA4: u8 = 0x4e;
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
        let (&op, rest) = self.remaining.split_first()?;
        match op {
            0x01..=0x4b => Some(
                self.take_slice(usize::from(op), rest)
                    .map(Instruction::PushBytes),
            ),
            opcode::OP_PUSHDATA1 => {
                let len = usize::try_from(self.read_len_le(1)).unwrap_or(usize::MAX);
                Some(
                    self.take_len_slice(len, 1, rest)
                        .map(Instruction::PushBytes),
                )
            }
            opcode::OP_PUSHDATA2 => {
                let len = usize::try_from(self.read_len_le(2)).unwrap_or(usize::MAX);
                Some(
                    self.take_len_slice(len, 2, rest)
                        .map(Instruction::PushBytes),
                )
            }
            opcode::OP_PUSHDATA4 => {
                let len = usize::try_from(self.read_len_le(4)).unwrap_or(usize::MAX);
                Some(
                    self.take_len_slice(len, 4, rest)
                        .map(Instruction::PushBytes),
                )
            }
            _ => {
                self.remaining = rest;
                if op == opcode::OP_0 {
                    Some(Ok(Instruction::PushBytes(&[])))
                } else {
                    Some(Ok(Instruction::Op(op)))
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
                if let Some(pushnum) = opcode::decode_pushnum(op)
                    && pushnum != num_pubkeys
                {
                    return false;
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

/// Encodes `data` as a minimal canonical push (direct push for 1..=75 bytes,
/// `OP_PUSHDATA1/2/4` above that).
#[must_use]
pub fn push_data(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut out = Vec::with_capacity(len + 5);
    if len < 76 {
        let len8 = u8::try_from(len).unwrap_or_else(|_| unreachable!("len < 76 fits u8"));
        out.push(len8);
    } else if let Ok(len8) = u8::try_from(len) {
        out.push(opcode::OP_PUSHDATA1);
        out.push(len8);
    } else if let Ok(len16) = u16::try_from(len) {
        out.push(opcode::OP_PUSHDATA2);
        out.extend_from_slice(&len16.to_le_bytes());
    } else {
        out.push(opcode::OP_PUSHDATA4);
        let len32 = u32::try_from(len).unwrap_or_else(|_| {
            unreachable!("u64 len exceeding u32 is not a pushable slice on 32-bit targets")
        });
        out.extend_from_slice(&len32.to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}
