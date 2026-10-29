//! BIP337 compressed-transaction codec (`compressrawtransaction` /
//! `decompressrawtransaction`).

use bitcoin::hashes::{Hash as _, hash160};
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin_rs_primitives::{
    Amount, LockTime, OutPoint, Script, Sequence, SighashCache, Tx, TxIn, TxOut, Txid, Witness,
    consensus_bytes, varint,
};
use hashbrown::HashMap;

use crate::error::RpcError;

pub(crate) const MAX_COMPRESSED_TX_BYTES: usize = 4_000_000;
pub(crate) const MAX_COMPRESSED_INPUTS: usize = 100_000;
pub(crate) const MAX_COMPRESSED_OUTPUTS: usize = 100_000;
pub(crate) const MAX_RETAINED_BODY_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_RETAINED_BODIES: usize = MAX_RETAINED_BODY_BYTES / MAX_COMPRESSED_TX_BYTES;
pub(crate) const MAX_RETAINED_INDEX_BYTES: usize = 12 * 1024 * 1024;
pub(crate) const MAX_RETAINED_BYTES_TOTAL: usize = 32 * 1024 * 1024;
pub(crate) const MAX_RESOLVER_STATE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_CUMULATIVE_BODY_LOADS: usize = MAX_RETAINED_BODIES * 2;
pub(crate) const MAX_CUMULATIVE_BODY_BYTES: usize = MAX_RETAINED_BODY_BYTES * 2;

/// Cancellation is polled once per this many codec inputs.
const CANCELLATION_POLL_INPUTS: usize = 256;

type FlatLookup = Option<Result<Option<u32>, LookupError>>;
type LocatedPrevoutLookup = Option<Result<Option<(OutPoint, ResolvedPrevout)>, LookupError>>;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CompressOptions {
    pub compress_outpoints: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedPrevout {
    pub txout: TxOut,
    pub confirmed_height: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Limit {
    Bodies,
    BodyBytes,
    Loads,
    LoadBytes,
    IndexBytes,
    State,
}

/// `Ok(None)` from a resolver method means "proved absent"; the error
/// variants mean "could not prove", and decompress refuses on them
/// rather than fabricating a prevout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LookupError {
    #[error("prevout context is unavailable")]
    Missing,
    #[error("block body at height {0} is unavailable")]
    BodyMissing(u32),
    #[error("block body at height {0} is corrupt")]
    CorruptBody(u32),
    #[error("block body at height {0} could not be read")]
    BodyReadFailed(u32),
    #[error("compressed transaction resource limit exceeded")]
    LimitExceeded(Limit),
    #[error("compressed transaction request cancelled")]
    Cancelled,
}

/// `flat_output_index` (cumulative outputs before `txid` in `height`,
/// plus `vout`) and `outpoint_at` must be exact inverses on one block;
/// the compressed form stores only the flat index.
pub(crate) trait PrevoutResolver {
    fn prevout(&mut self, outpoint: &OutPoint) -> Result<Option<ResolvedPrevout>, LookupError>;
    fn flat_output_index(
        &mut self,
        height: u32,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<u32>, LookupError>;
    fn outpoint_at(
        &mut self,
        height: u32,
        flat_index: u32,
    ) -> Result<Option<(OutPoint, ResolvedPrevout)>, LookupError>;
    fn cancelled(&self) -> bool;
}

/// Codec failure.
///
/// Each variant maps to exactly one [`RpcError`]: structural malformation is `-22`,
/// oversize input or output is `-8`, budget exhaustion and cancellation are retryable
/// `-1`, a proved-absent prevout during decompress is `-5`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CodecError {
    #[error("compressed transaction is truncated")]
    Truncated,
    #[error("compressed transaction is not canonically encoded")]
    NonCanonical,
    #[error("compressed transaction value exceeds its supported range")]
    Overflow,
    #[error("compressed transaction resource limit exceeded")]
    LimitExceeded(Limit),
    #[error("compressed transaction has no inputs or outputs")]
    EmptyTransaction,
    #[error("compressed transaction spends an unsupported script type")]
    UnsupportedScript,
    #[error("failed to compute sighash for compressed signature recovery")]
    Sighash,
    #[error("prevout is unavailable for decompression")]
    PrevoutMissing(OutPoint),
    #[error("block body at height {0} is unavailable")]
    BodyMissing(u32),
    #[error("block body at height {0} is corrupt")]
    CorruptBody(u32),
    #[error("block body at height {0} could not be read")]
    BodyReadFailed(u32),
    #[error("compressed signature could not be recovered")]
    SignatureUnrecoverable,
    #[error("compressed transaction request cancelled")]
    Cancelled,
}

impl From<CodecError> for RpcError {
    fn from(error: CodecError) -> Self {
        match error {
            CodecError::Truncated
            | CodecError::NonCanonical
            | CodecError::EmptyTransaction
            | CodecError::UnsupportedScript
            | CodecError::Sighash
            | CodecError::SignatureUnrecoverable => Self::Deserialization(error.to_string()),
            CodecError::Overflow => Self::InvalidParameter(error.to_string()),
            CodecError::LimitExceeded(_) | CodecError::Cancelled => Self::Misc(error.to_string()),
            CodecError::PrevoutMissing(_) => Self::NotFound("prevout not found"),
            CodecError::BodyMissing(height) => Self::Misc(format!(
                "block body at height {height} is unavailable; retry when history is present"
            )),
            CodecError::CorruptBody(height) => {
                Self::Misc(format!("block body at height {height} is corrupt"))
            }
            CodecError::BodyReadFailed(height) => Self::Misc(format!(
                "block body at height {height} could not be read; retry"
            )),
        }
    }
}

fn lookup_failure(error: LookupError, missing: CodecError) -> CodecError {
    match error {
        LookupError::Missing => missing,
        LookupError::BodyMissing(height) => CodecError::BodyMissing(height),
        LookupError::CorruptBody(height) => CodecError::CorruptBody(height),
        LookupError::BodyReadFailed(height) => CodecError::BodyReadFailed(height),
        LookupError::LimitExceeded(limit) => CodecError::LimitExceeded(limit),
        LookupError::Cancelled => CodecError::Cancelled,
    }
}

/// Encodes the carry-aware Core VARINT (chainstate form).
///
/// At most ten bytes, so every `u64` amount has a spelling; larger spellings are
/// impossible on this domain. `u32`-range values keep their short (at most five-byte)
/// spelling, which the capped readers below rely on.
fn write_varint(value: u64, out: &mut Vec<u8>) -> Result<(), CodecError> {
    let mut tmp = [0_u8; 10];
    let mut len = 0_usize;
    let mut current = value;
    loop {
        let low = u8::try_from(current & 0x7f).map_err(|_| CodecError::Overflow)?;
        tmp[len] = if len == 0 { low } else { low | 0x80 };
        len += 1;
        if current <= 0x7f {
            break;
        }
        current = (current >> 7) - 1;
    }
    if len > 10 {
        return Err(CodecError::Overflow);
    }
    for index in (0..len).rev() {
        out.push(tmp[index]);
    }
    Ok(())
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn write(&mut self, data: &[u8]) -> Result<(), CodecError> {
        let total = self
            .bytes
            .len()
            .checked_add(data.len())
            .ok_or(CodecError::Overflow)?;
        if total > MAX_COMPRESSED_TX_BYTES {
            return Err(CodecError::Overflow);
        }
        self.bytes.extend_from_slice(data);
        Ok(())
    }

    fn write_u8(&mut self, byte: u8) -> Result<(), CodecError> {
        self.write(&[byte])
    }

    fn write_compact_size(&mut self, value: u64) -> Result<(), CodecError> {
        self.write(&varint::encode(value))
    }

    fn write_varint(&mut self, value: u64) -> Result<(), CodecError> {
        let mut encoded = Vec::new();
        write_varint(value, &mut encoded)?;
        self.write(&encoded)
    }

    fn write_vlp(&mut self, data: &[u8]) -> Result<(), CodecError> {
        self.write_varint(u64::try_from(data.len()).map_err(|_| CodecError::Overflow)?)?;
        self.write(data)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(len).ok_or(CodecError::Overflow)?;
        let slice = self.bytes.get(self.pos..end).ok_or(CodecError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn read_compact_size(&mut self) -> Result<u64, CodecError> {
        let (value, consumed) =
            varint::decode(&self.bytes[self.pos..]).map_err(|error| match error {
                varint::VarintError::Truncated { .. } => CodecError::Truncated,
                varint::VarintError::NonCanonical { .. } => CodecError::NonCanonical,
            })?;
        self.pos += consumed;
        Ok(value)
    }

    fn read_varint(&mut self) -> Result<u64, CodecError> {
        self.read_varint_capped(10)
    }

    fn read_varint_capped(&mut self, max_bytes: usize) -> Result<u64, CodecError> {
        let start = self.pos;
        let mut value = 0_u64;
        for _ in 0..max_bytes {
            let byte = self.read_u8()?;
            value = value
                .checked_mul(128)
                .and_then(|v| v.checked_add(u64::from(byte & 0x7f)))
                .ok_or(CodecError::Overflow)?;
            if byte & 0x80 == 0 {
                let mut canonical = Vec::new();
                write_varint(value, &mut canonical)?;
                if canonical != self.bytes[start..self.pos] {
                    return Err(CodecError::NonCanonical);
                }
                return Ok(value);
            }
            value = value.checked_add(1).ok_or(CodecError::Overflow)?;
        }
        Err(CodecError::Overflow)
    }

    fn read_vlp(&mut self) -> Result<&'a [u8], CodecError> {
        let len = self.read_varint_capped(5)?;
        let len = usize::try_from(len).map_err(|_| CodecError::Overflow)?;
        self.take(len)
    }
}

fn read_u32_varint(reader: &mut Reader<'_>) -> Result<u32, CodecError> {
    u32::try_from(reader.read_varint_capped(5)?).map_err(|_| CodecError::Overflow)
}

fn read_u32_compact_size(reader: &mut Reader<'_>) -> Result<u32, CodecError> {
    u32::try_from(reader.read_compact_size()?).map_err(|_| CodecError::Overflow)
}

fn encode_bits(inputs: &[u8], outputs: &[u8]) -> Vec<u8> {
    let total_bits = inputs.len() * 6 + outputs.len() * 3;
    let mut packed = vec![0_u8; total_bits.div_ceil(8)];
    let mut bit_pos = 0_usize;
    let push = |value: u8, width: usize, packed: &mut Vec<u8>, bit_pos: &mut usize| {
        for shift in (0..width).rev() {
            if (value >> shift) & 1 == 1 {
                packed[*bit_pos / 8] |= 0x80 >> (*bit_pos % 8);
            }
            *bit_pos += 1;
        }
    };
    for value in inputs {
        push(*value, 6, &mut packed, &mut bit_pos);
    }
    for value in outputs {
        push(*value, 3, &mut packed, &mut bit_pos);
    }
    packed
}

fn decode_bits(
    reader: &mut Reader<'_>,
    inputs: usize,
    outputs: usize,
) -> Result<(Vec<u8>, Vec<u8>), CodecError> {
    let total_bits = inputs * 6 + outputs * 3;
    let byte_len = total_bits.div_ceil(8);
    let packed = reader.take(byte_len)?;
    let mut bit_pos = 0_usize;
    let take_bits = |width: usize, packed: &[u8], bit_pos: &mut usize| -> u8 {
        let mut value = 0_u8;
        for _ in 0..width {
            let bit = (packed[*bit_pos / 8] >> (7 - (*bit_pos % 8))) & 1;
            value = (value << 1) | bit;
            *bit_pos += 1;
        }
        value
    };
    let mut input_meta = Vec::with_capacity(inputs);
    for _ in 0..inputs {
        input_meta.push(take_bits(6, packed, &mut bit_pos));
    }
    let mut output_meta = Vec::with_capacity(outputs);
    for _ in 0..outputs {
        output_meta.push(take_bits(3, packed, &mut bit_pos));
    }
    for index in total_bits..byte_len * 8 {
        if (packed[index / 8] >> (7 - (index % 8))) & 1 == 1 {
            return Err(CodecError::NonCanonical);
        }
    }
    Ok((input_meta, output_meta))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputShape {
    Custom,
    P2pkUncompressed,
    P2pkCompressed,
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
}

fn output_shape(script: &[u8]) -> (OutputShape, &[u8]) {
    if script.len() == 67 && script[0] == 0x41 && script[66] == 0xac {
        return (OutputShape::P2pkUncompressed, &script[1..66]);
    }
    if script.len() == 35 && script[0] == 0x21 && script[34] == 0xac {
        return (OutputShape::P2pkCompressed, &script[1..34]);
    }
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return (OutputShape::P2pkh, &script[3..23]);
    }
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        return (OutputShape::P2sh, &script[2..22]);
    }
    if script.len() == 22 && script[0] == 0x00 && script[1] == 0x14 {
        return (OutputShape::P2wpkh, &script[2..22]);
    }
    if script.len() == 34 && script[0] == 0x00 && script[1] == 0x20 {
        return (OutputShape::P2wsh, &script[2..34]);
    }
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        return (OutputShape::P2tr, &script[2..34]);
    }
    (OutputShape::Custom, script)
}

fn output_code(shape: OutputShape) -> u8 {
    match shape {
        OutputShape::Custom => 0,
        OutputShape::P2pkUncompressed => 1,
        OutputShape::P2pkCompressed => 2,
        OutputShape::P2pkh => 3,
        OutputShape::P2sh => 4,
        OutputShape::P2wpkh => 5,
        OutputShape::P2wsh => 6,
        OutputShape::P2tr => 7,
    }
}

fn output_script(code: u8, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    let script = match (code, payload.len()) {
        (1, 65) => {
            let mut script = Vec::with_capacity(67);
            script.push(0x41);
            script.extend_from_slice(payload);
            script.push(0xac);
            script
        }
        (2, 33) => {
            let mut script = Vec::with_capacity(35);
            script.push(0x21);
            script.extend_from_slice(payload);
            script.push(0xac);
            script
        }
        (3, 20) => {
            let mut script = Vec::with_capacity(25);
            script.extend_from_slice(&[0x76, 0xa9, 0x14]);
            script.extend_from_slice(payload);
            script.extend_from_slice(&[0x88, 0xac]);
            script
        }
        (4, 20) => {
            let mut script = Vec::with_capacity(23);
            script.extend_from_slice(&[0xa9, 0x14]);
            script.extend_from_slice(payload);
            script.push(0x87);
            script
        }
        (5, 20) => {
            let mut script = Vec::with_capacity(22);
            script.extend_from_slice(&[0x00, 0x14]);
            script.extend_from_slice(payload);
            script
        }
        (6, 32) => {
            let mut script = Vec::with_capacity(34);
            script.extend_from_slice(&[0x00, 0x20]);
            script.extend_from_slice(payload);
            script
        }
        (7, 32) => {
            let mut script = Vec::with_capacity(34);
            script.extend_from_slice(&[0x51, 0x20]);
            script.extend_from_slice(payload);
            script
        }
        _ => return Err(CodecError::NonCanonical),
    };
    Ok(script)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrevoutKind {
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
    P2wpkh([u8; 20]),
    P2wsh,
    P2tr,
    Other,
}

fn prevout_kind(script: &[u8]) -> PrevoutKind {
    match output_shape(script) {
        (OutputShape::P2pkh, payload) => {
            PrevoutKind::P2pkh(payload.try_into().unwrap_or([0_u8; 20]))
        }
        (OutputShape::P2sh, payload) => PrevoutKind::P2sh(payload.try_into().unwrap_or([0_u8; 20])),
        (OutputShape::P2wpkh, payload) => {
            PrevoutKind::P2wpkh(payload.try_into().unwrap_or([0_u8; 20]))
        }
        (OutputShape::P2wsh, _) => PrevoutKind::P2wsh,
        (OutputShape::P2tr, _) => PrevoutKind::P2tr,
        _ => PrevoutKind::Other,
    }
}

fn hash160_20(data: &[u8]) -> [u8; 20] {
    *hash160::Hash::hash(data).as_byte_array()
}

fn push_data(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 3);
    match data.len() {
        len if len < 76 => {
            out.push(u8::try_from(len).unwrap_or(0));
        }
        len if len <= 0xff => {
            out.push(0x4c);
            out.push(u8::try_from(len).unwrap_or(0));
        }
        len => {
            out.push(0x4d);
            let len = u16::try_from(len).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_le_bytes());
        }
    }
    out.extend_from_slice(data);
    out
}

fn read_push(script: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    let opcode = *script.get(pos)?;
    let (len, header) = match opcode {
        0 => (0_usize, 1_usize),
        1..=75 => (usize::from(opcode), 1_usize),
        0x4c => (usize::from(*script.get(pos + 1)?), 2_usize),
        0x4d => (
            usize::from(u16::from_le_bytes([
                *script.get(pos + 1)?,
                *script.get(pos + 2)?,
            ])),
            3_usize,
        ),
        0x4e => (
            usize::try_from(u32::from_le_bytes([
                *script.get(pos + 1)?,
                *script.get(pos + 2)?,
                *script.get(pos + 3)?,
                *script.get(pos + 4)?,
            ]))
            .ok()?,
            5_usize,
        ),
        _ => return None,
    };
    let start = pos.checked_add(header)?;
    let end = start.checked_add(len)?;
    Some((script.get(start..end)?, end))
}

fn der_encode(sig64: &[u8; 64]) -> Vec<u8> {
    fn integer(half: &[u8]) -> Vec<u8> {
        let mut start = 0_usize;
        while start + 1 < half.len() && half[start] == 0 {
            start += 1;
        }
        let trimmed = &half[start..];
        let mut out = Vec::with_capacity(trimmed.len() + 1);
        if trimmed.first().is_some_and(|byte| byte & 0x80 != 0) {
            out.push(0);
        }
        out.extend_from_slice(trimmed);
        out
    }
    let r = integer(&sig64[..32]);
    let s = integer(&sig64[32..]);
    let mut der = Vec::with_capacity(r.len() + s.len() + 6);
    der.push(0x30);
    der.push(u8::try_from(r.len() + s.len() + 4).unwrap_or(0));
    der.push(0x02);
    der.push(u8::try_from(r.len()).unwrap_or(0));
    der.extend_from_slice(&r);
    der.push(0x02);
    der.push(u8::try_from(s.len()).unwrap_or(0));
    der.extend_from_slice(&s);
    der
}

struct CompressedSig {
    sig: [u8; 64],
    pubkey_hash: Option<[u8; 20]>,
    hash_type: Option<u8>,
    /// Standard hash type: `0x01` ECDSA, `0x00` (absent byte) taproot.
    standard: bool,
}

fn ecdsa_compressed(sig_item: &[u8]) -> Option<CompressedSig> {
    let (der, hash_type) = sig_item.split_at(sig_item.len().checked_sub(1)?);
    let hash_type = *hash_type.first()?;
    let signature = Signature::from_der(der).ok()?;
    Some(CompressedSig {
        sig: signature.serialize_compact(),
        pubkey_hash: None,
        hash_type: (hash_type != 1).then_some(hash_type),
        standard: hash_type == 1,
    })
}

/// Extracts the compressed form of `input`'s signature when the prevout
/// kind is in the closed compressible set and the authorization has the
/// exact expected shape; `None` selects the uncompressed envelope.
fn compressed_signature(input: &TxIn, kind: &PrevoutKind) -> Option<CompressedSig> {
    match kind {
        PrevoutKind::P2tr => {
            if !input.script_sig.is_empty() || input.witness.len() != 1 {
                return None;
            }
            let item = input.witness.first()?;
            match item.len() {
                64 => Some(CompressedSig {
                    sig: item.as_slice().try_into().ok()?,
                    pubkey_hash: None,
                    hash_type: None,
                    standard: true,
                }),
                65 => {
                    let (sig, hash_type) = item.split_at(64);
                    Some(CompressedSig {
                        sig: sig.try_into().ok()?,
                        pubkey_hash: None,
                        hash_type: Some(*hash_type.first()?),
                        standard: false,
                    })
                }
                _ => None,
            }
        }
        PrevoutKind::P2pkh(expected) => {
            if !input.witness.is_empty() {
                return None;
            }
            let script = input.script_sig.as_bytes();
            let (sig_item, pos) = read_push(script, 0)?;
            let (pubkey, end) = read_push(script, pos)?;
            if end != script.len() {
                return None;
            }
            let mut canonical = push_data(sig_item);
            canonical.extend_from_slice(&push_data(pubkey));
            if canonical != script {
                return None;
            }
            let compressed = pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03);
            if !compressed && (pubkey.len() != 65 || pubkey.first() != Some(&0x04)) {
                return None;
            }
            if hash160_20(pubkey) != *expected {
                return None;
            }
            ecdsa_compressed(sig_item)
        }
        PrevoutKind::P2wpkh(expected) => {
            if !input.script_sig.is_empty() || input.witness.len() != 2 {
                return None;
            }
            let pubkey = input.witness.get(1)?;
            if pubkey.len() != 33 || hash160_20(pubkey) != *expected {
                return None;
            }
            ecdsa_compressed(input.witness.first()?)
        }
        PrevoutKind::P2sh(script_hash) => {
            let script_sig = input.script_sig.as_bytes();
            if script_sig.len() != 23
                || script_sig[0] != 0x16
                || script_sig[1] != 0x00
                || script_sig[2] != 0x14
            {
                return None;
            }
            if input.witness.len() != 2 {
                return None;
            }
            let pubkey = input.witness.get(1)?;
            if pubkey.len() != 33 {
                return None;
            }
            let redeem_hash: [u8; 20] = script_sig[3..23].try_into().ok()?;
            if hash160_20(pubkey) != redeem_hash || hash160_20(&script_sig[1..]) != *script_hash {
                return None;
            }
            let mut compressed = ecdsa_compressed(input.witness.first()?)?;
            compressed.pubkey_hash = Some(redeem_hash);
            Some(compressed)
        }
        PrevoutKind::P2wsh | PrevoutKind::Other => None,
    }
}

fn sequence_code(sequence: u32) -> u8 {
    match sequence {
        0 => 1,
        0xffff_fffe => 2,
        0xffff_ffff => 3,
        _ => 0,
    }
}

fn sequence_value(code: u8, reader: &mut Reader<'_>) -> Result<u32, CodecError> {
    match code {
        0 => read_u32_varint(reader),
        1 => Ok(0),
        2 => Ok(0xffff_fffe),
        _ => Ok(0xffff_ffff),
    }
}

fn flat_lookup_groups(
    tx: &Tx,
    resolved: &[Option<ResolvedPrevout>],
    degraded: &[Option<String>],
) -> (Vec<u32>, HashMap<u32, Vec<usize>>) {
    let mut order: Vec<u32> = Vec::new();
    let mut members: HashMap<u32, Vec<usize>> = HashMap::new();
    for (index, _) in tx.inputs.iter().enumerate() {
        if degraded.get(index).and_then(Option::as_ref).is_some() {
            continue;
        }
        let Some(prevout) = resolved.get(index).and_then(Option::as_ref) else {
            continue;
        };
        let Some(height) = prevout.confirmed_height else {
            continue;
        };
        if !members.contains_key(&height) {
            order.push(height);
        }
        members.entry(height).or_default().push(index);
    }
    (order, members)
}

fn resolve_flats_grouped(
    tx: &Tx,
    resolver: &mut dyn PrevoutResolver,
    order: &[u32],
    members: &HashMap<u32, Vec<usize>>,
) -> Result<Vec<FlatLookup>, CodecError> {
    let mut results: Vec<FlatLookup> = vec![None; tx.inputs.len()];
    let mut polls = 0_usize;
    for &height in order {
        let Some(indices) = members.get(&height) else {
            continue;
        };
        for &index in indices {
            if polls.is_multiple_of(CANCELLATION_POLL_INPUTS) && resolver.cancelled() {
                return Err(CodecError::Cancelled);
            }
            polls += 1;
            let input = &tx.inputs[index];
            results[index] = Some(resolver.flat_output_index(
                height,
                &input.previous_output.txid,
                input.previous_output.vout,
            ));
        }
    }
    Ok(results)
}

struct Plan {
    outpoint_compressed: bool,
    height_offset: u64,
    flat_index: u64,
    signature: Option<CompressedSig>,
    sequence: u32,
}

/// Compresses `tx`. Missing contextual facts degrade a single input to
/// its raw outpoint with one `UTXO(i): <reason>` warning; retained
/// budget exhaustion and cancellation are errors, never downgrades.
#[allow(
    clippy::too_many_lines,
    reason = "one sequential encoding pass over the transaction fields"
)]
pub(crate) fn compress_transaction(
    tx: &Tx,
    resolver: &mut dyn PrevoutResolver,
    options: CompressOptions,
) -> Result<(Vec<u8>, Vec<String>), CodecError> {
    if tx.inputs.is_empty() || tx.outputs.is_empty() {
        return Err(CodecError::EmptyTransaction);
    }
    if tx.inputs.len() > MAX_COMPRESSED_INPUTS || tx.outputs.len() > MAX_COMPRESSED_OUTPUTS {
        return Err(CodecError::Overflow);
    }
    if consensus_bytes(tx).len() > MAX_COMPRESSED_TX_BYTES {
        return Err(CodecError::Overflow);
    }

    let mut resolved: Vec<Option<ResolvedPrevout>> = Vec::with_capacity(tx.inputs.len());
    let mut degraded: Vec<Option<String>> = Vec::with_capacity(tx.inputs.len());
    for (index, input) in tx.inputs.iter().enumerate() {
        if index % CANCELLATION_POLL_INPUTS == 0 && resolver.cancelled() {
            return Err(CodecError::Cancelled);
        }
        match resolver.prevout(&input.previous_output) {
            Ok(prevout) => {
                degraded.push(None);
                resolved.push(prevout);
            }
            Err(LookupError::LimitExceeded(limit)) => {
                return Err(CodecError::LimitExceeded(limit));
            }
            Err(LookupError::Cancelled) => return Err(CodecError::Cancelled),
            Err(error) => {
                let reason = match error {
                    LookupError::Missing => "prevout context is unavailable".to_owned(),
                    LookupError::BodyMissing(height) => {
                        format!("prevout block body at height {height} is unavailable")
                    }
                    LookupError::CorruptBody(height) => {
                        format!("prevout block body at height {height} is corrupt")
                    }
                    LookupError::BodyReadFailed(height) => {
                        format!("prevout block body at height {height} could not be read")
                    }
                    LookupError::LimitExceeded(_) | LookupError::Cancelled => {
                        "prevout context is unavailable".to_owned()
                    }
                };
                degraded.push(Some(reason));
                resolved.push(None);
            }
        }
    }

    let locktime = tx.lock_time.to_consensus();
    let mut min_height: Option<u32> = if locktime != 0 {
        Some(locktime - 1)
    } else {
        None
    };
    if options.compress_outpoints {
        for prevout in resolved.iter().flatten() {
            if let Some(height) = prevout.confirmed_height {
                let candidate = height.saturating_sub(1);
                min_height = Some(min_height.map_or(candidate, |m: u32| m.min(candidate)));
            }
        }
    }
    let min_height = min_height.unwrap_or(0);

    let flat_results = if options.compress_outpoints {
        let (order, members) = flat_lookup_groups(tx, &resolved, &degraded);
        resolve_flats_grouped(tx, resolver, &order, &members)?
    } else {
        vec![None; tx.inputs.len()]
    };

    let mut plans: Vec<Plan> = Vec::with_capacity(tx.inputs.len());
    let mut warnings: Vec<String> = Vec::new();
    for (index, input) in tx.inputs.iter().enumerate() {
        let prevout = resolved.get(index).and_then(Option::as_ref);
        let signature = prevout.and_then(|prevout| {
            compressed_signature(input, &prevout_kind(prevout.txout.script_pubkey.as_bytes()))
        });
        let mut outpoint_compressed = false;
        let mut height_offset = 0_u64;
        let mut flat_index = 0_u64;
        if options.compress_outpoints {
            let reason = match (prevout, degraded.get(index).and_then(Option::as_ref)) {
                (_, Some(reason)) => Some(reason.clone()),
                (None, None) => Some("prevout not found".to_owned()),
                (Some(prevout), None) => match prevout.confirmed_height {
                    None => Some("prevout is unconfirmed".to_owned()),
                    Some(height) => match flat_results[index] {
                        Some(Ok(Some(flat))) => {
                            height_offset = u64::from(
                                height.checked_sub(min_height).ok_or(CodecError::Overflow)?,
                            );
                            flat_index = u64::from(flat);
                            outpoint_compressed = true;
                            None
                        }
                        Some(Ok(None)) => {
                            Some("prevout transaction not found in its block".to_owned())
                        }
                        Some(Err(LookupError::LimitExceeded(limit))) => {
                            return Err(CodecError::LimitExceeded(limit));
                        }
                        Some(Err(LookupError::Cancelled)) => return Err(CodecError::Cancelled),
                        Some(Err(LookupError::Missing)) => {
                            Some("prevout context is unavailable".to_owned())
                        }
                        Some(Err(LookupError::BodyMissing(h))) => {
                            Some(format!("prevout block body at height {h} is unavailable"))
                        }
                        Some(Err(LookupError::CorruptBody(h))) => {
                            Some(format!("prevout block body at height {h} is corrupt"))
                        }
                        Some(Err(LookupError::BodyReadFailed(h))) => Some(format!(
                            "prevout block body at height {h} could not be read"
                        )),
                        None => Some("prevout context is unavailable".to_owned()),
                    },
                },
            };
            if let Some(reason) = reason {
                warnings.push(format!("UTXO({index}): {reason}"));
            }
        }
        plans.push(Plan {
            outpoint_compressed,
            height_offset,
            flat_index,
            signature,
            sequence: input.sequence.to_consensus(),
        });
    }

    let flag = |value: u32| -> u8 {
        if (1..=3).contains(&value) {
            u8::try_from(value).unwrap_or(0)
        } else {
            0
        }
    };
    let input_count = u32::try_from(tx.inputs.len()).map_err(|_| CodecError::Overflow)?;
    let output_count = u32::try_from(tx.outputs.len()).map_err(|_| CodecError::Overflow)?;
    let mut metadata = flag(tx.version);
    metadata |= flag(input_count) << 2;
    metadata |= flag(output_count) << 4;
    if locktime != 0 {
        metadata |= 1 << 6;
    }
    if min_height != 0 {
        metadata |= 1 << 7;
    }

    let mut writer = Writer::new();
    writer.write_u8(metadata)?;
    if flag(tx.version) == 0 {
        writer.write_compact_size(u64::from(tx.version))?;
    }
    if flag(input_count) == 0 {
        writer.write_compact_size(u64::from(input_count))?;
    }
    if flag(output_count) == 0 {
        writer.write_compact_size(u64::from(output_count))?;
    }
    if locktime != 0 {
        let stored = locktime
            .checked_sub(min_height)
            .ok_or(CodecError::Overflow)?;
        writer.write_compact_size(u64::from(stored))?;
    }
    if min_height != 0 {
        writer.write_varint(u64::from(min_height))?;
    }

    let mut input_meta: Vec<u8> = Vec::with_capacity(plans.len());
    for plan in &plans {
        let mut meta = 0_u8;
        if let Some(signature) = &plan.signature {
            meta |= 1;
            if signature.pubkey_hash.is_some() {
                meta |= 1 << 1;
            }
            if signature.standard {
                meta |= 1 << 2;
            }
        }
        meta |= sequence_code(plan.sequence) << 3;
        if plan.outpoint_compressed {
            meta |= 1 << 5;
        }
        input_meta.push(meta);
    }
    let mut output_meta: Vec<u8> = Vec::with_capacity(tx.outputs.len());
    for output in &tx.outputs {
        output_meta.push(output_code(output_shape(output.script_pubkey.as_bytes()).0));
    }
    writer.write(&encode_bits(&input_meta, &output_meta))?;

    for (index, (input, plan)) in tx.inputs.iter().zip(plans.iter()).enumerate() {
        let _ = index;
        if plan.outpoint_compressed {
            writer.write_varint(plan.height_offset)?;
            writer.write_varint(plan.flat_index)?;
        } else {
            writer.write(input.previous_output.txid.as_bytes())?;
            writer.write_compact_size(u64::from(input.previous_output.vout))?;
        }
        if let Some(signature) = &plan.signature {
            writer.write(&signature.sig)?;
            if let Some(pubkey_hash) = &signature.pubkey_hash {
                writer.write(pubkey_hash)?;
            }
            if !signature.standard {
                writer.write_u8(signature.hash_type.ok_or(CodecError::NonCanonical)?)?;
            }
        } else {
            writer.write_vlp(input.script_sig.as_bytes())?;
            writer.write_varint(
                u64::try_from(input.witness.len()).map_err(|_| CodecError::Overflow)?,
            )?;
            for item in &input.witness {
                writer.write_vlp(item)?;
            }
        }
        if sequence_code(plan.sequence) == 0 {
            writer.write_varint(u64::from(plan.sequence))?;
        }
    }

    for output in &tx.outputs {
        let (shape, payload) = output_shape(output.script_pubkey.as_bytes());
        if shape == OutputShape::Custom {
            writer.write_vlp(payload)?;
        } else {
            writer.write(payload)?;
        }
        writer.write_varint(output.value.to_sat())?;
    }

    Ok((writer.bytes, warnings))
}

enum SigParts {
    Compressed {
        sig: [u8; 64],
        pubkey_hash: Option<[u8; 20]>,
        hash_type: Option<u8>,
        standard: bool,
    },
    Uncompressed {
        script_sig: Vec<u8>,
        witness: Vec<Vec<u8>>,
    },
}

struct ParsedInput {
    height_flat: Option<(u32, u32)>,
    raw_outpoint: Option<OutPoint>,
    sequence: u32,
    signature: SigParts,
}

struct InputParts {
    outpoint: OutPoint,
    resolved: Option<ResolvedPrevout>,
    sequence: u32,
    signature: SigParts,
}

struct Recovery<'a> {
    index: usize,
    sig: &'a [u8; 64],
    hash_type: u8,
    kind: &'a PrevoutKind,
    prevout: &'a ResolvedPrevout,
    stored_pkh: Option<&'a [u8; 20]>,
}

fn recover_pubkey(cache: &SighashCache<'_>, request: &Recovery<'_>) -> Result<Vec<u8>, CodecError> {
    let digest = match request.kind {
        PrevoutKind::P2pkh(_) => cache
            .legacy_signature_hash(
                request.index,
                request.prevout.txout.script_pubkey.as_bytes(),
                u32::from(request.hash_type),
            )
            .map_err(|_| CodecError::Sighash)?,
        PrevoutKind::P2wpkh(hash) | PrevoutKind::P2sh(hash) => {
            let script_hash = match request.kind {
                PrevoutKind::P2wpkh(hash) => hash,
                PrevoutKind::P2sh(_) => request.stored_pkh.ok_or(CodecError::UnsupportedScript)?,
                _ => hash,
            };
            let mut script_code = Vec::with_capacity(25);
            script_code.extend_from_slice(&[0x76, 0xa9, 0x14]);
            script_code.extend_from_slice(script_hash);
            script_code.extend_from_slice(&[0x88, 0xac]);
            cache
                .segwit_v0_signature_hash_raw(
                    request.index,
                    &script_code,
                    request.prevout.txout.value,
                    u32::from(request.hash_type),
                )
                .map_err(|_| CodecError::Sighash)?
        }
        PrevoutKind::P2wsh | PrevoutKind::P2tr | PrevoutKind::Other => {
            return Err(CodecError::UnsupportedScript);
        }
    };
    let message = Message::from_digest(*digest.as_byte_array());
    let secp = Secp256k1::verification_only();
    for recovery in 0..=3_i32 {
        let Ok(recovery_id) = RecoveryId::from_i32(recovery) else {
            continue;
        };
        let Ok(recoverable) = RecoverableSignature::from_compact(request.sig, recovery_id) else {
            continue;
        };
        let Ok(public) = secp.recover_ecdsa(&message, &recoverable) else {
            continue;
        };
        let compressed = public.serialize();
        match request.kind {
            PrevoutKind::P2pkh(hash) => {
                if hash160_20(&compressed) == *hash {
                    return Ok(compressed.to_vec());
                }
                let uncompressed = public.serialize_uncompressed();
                if hash160_20(&uncompressed) == *hash {
                    return Ok(uncompressed.to_vec());
                }
            }
            PrevoutKind::P2wpkh(hash) => {
                if hash160_20(&compressed) == *hash {
                    return Ok(compressed.to_vec());
                }
            }
            PrevoutKind::P2sh(_) => {
                if request
                    .stored_pkh
                    .is_some_and(|pkh| hash160_20(&compressed) == *pkh)
                {
                    return Ok(compressed.to_vec());
                }
            }
            PrevoutKind::P2wsh | PrevoutKind::P2tr | PrevoutKind::Other => {
                return Err(CodecError::UnsupportedScript);
            }
        }
    }
    Err(CodecError::SignatureUnrecoverable)
}

fn resolve_outpoints_grouped(
    parsed: &[ParsedInput],
    resolver: &mut dyn PrevoutResolver,
) -> Result<Vec<LocatedPrevoutLookup>, CodecError> {
    let mut order: Vec<u32> = Vec::new();
    let mut members: HashMap<u32, Vec<usize>> = HashMap::new();
    for (index, part) in parsed.iter().enumerate() {
        if let Some((height, _)) = part.height_flat {
            if !members.contains_key(&height) {
                order.push(height);
            }
            members.entry(height).or_default().push(index);
        }
    }
    let mut located: Vec<LocatedPrevoutLookup> = vec![None; parsed.len()];
    let mut polls = 0_usize;
    for &height in &order {
        let Some(indices) = members.get(&height) else {
            continue;
        };
        for &index in indices {
            if polls.is_multiple_of(CANCELLATION_POLL_INPUTS) && resolver.cancelled() {
                return Err(CodecError::Cancelled);
            }
            polls += 1;
            let Some((_, flat)) = parsed[index].height_flat else {
                continue;
            };
            located[index] = Some(resolver.outpoint_at(height, flat));
        }
    }
    Ok(located)
}

fn resolve_sig_prevout(
    resolver: &mut dyn PrevoutResolver,
    outpoint: &OutPoint,
    resolved: Option<ResolvedPrevout>,
) -> Result<Option<ResolvedPrevout>, CodecError> {
    match resolved {
        Some(prevout) => Ok(Some(prevout)),
        None => match resolver.prevout(outpoint) {
            Ok(Some(prevout)) => Ok(Some(prevout)),
            Ok(None) => Err(CodecError::PrevoutMissing(*outpoint)),
            Err(error) => Err(lookup_failure(error, CodecError::PrevoutMissing(*outpoint))),
        },
    }
}

pub(crate) struct DecompressPlan {
    tx: Tx,
    inputs: Vec<InputParts>,
}

#[allow(
    clippy::too_many_lines,
    reason = "one sequential decoding pass over the transaction fields"
)]
pub(crate) fn decompress_prepare(
    bytes: &[u8],
    resolver: &mut dyn PrevoutResolver,
) -> Result<DecompressPlan, CodecError> {
    if bytes.len() > MAX_COMPRESSED_TX_BYTES {
        return Err(CodecError::Overflow);
    }
    let mut reader = Reader::new(bytes);
    let metadata = reader.read_u8()?;
    let version_flag = metadata & 0x03;
    let input_flag = (metadata >> 2) & 0x03;
    let output_flag = (metadata >> 4) & 0x03;
    let has_locktime = metadata & 0x40 != 0;
    let has_min_height = metadata & 0x80 != 0;

    let version = if version_flag == 0 {
        read_u32_compact_size(&mut reader)?
    } else {
        u32::from(version_flag)
    };
    let input_count = if input_flag == 0 {
        usize::try_from(reader.read_compact_size()?).map_err(|_| CodecError::Overflow)?
    } else {
        usize::from(input_flag)
    };
    let output_count = if output_flag == 0 {
        usize::try_from(reader.read_compact_size()?).map_err(|_| CodecError::Overflow)?
    } else {
        usize::from(output_flag)
    };
    if input_count == 0 || output_count == 0 {
        return Err(CodecError::EmptyTransaction);
    }
    if input_count > MAX_COMPRESSED_INPUTS || output_count > MAX_COMPRESSED_OUTPUTS {
        return Err(CodecError::Overflow);
    }
    let stored_locktime = if has_locktime {
        Some(reader.read_compact_size()?)
    } else {
        None
    };
    let min_height = if has_min_height {
        read_u32_varint(&mut reader)?
    } else {
        0
    };
    let locktime = match stored_locktime {
        Some(stored) => {
            let stored = u32::try_from(stored).map_err(|_| CodecError::Overflow)?;
            min_height.checked_add(stored).ok_or(CodecError::Overflow)?
        }
        None => 0,
    };

    let (input_meta, output_meta) = decode_bits(&mut reader, input_count, output_count)?;

    let mut parsed: Vec<ParsedInput> = Vec::with_capacity(input_count);
    for index in 0..input_count {
        if index % CANCELLATION_POLL_INPUTS == 0 && resolver.cancelled() {
            return Err(CodecError::Cancelled);
        }
        let meta = *input_meta.get(index).ok_or(CodecError::Truncated)?;
        let sig_compressed = meta & 1 != 0;
        let pkh_present = meta & 0x02 != 0;
        let standard = meta & 0x04 != 0;
        let seq_code = (meta >> 3) & 0x03;
        let outpoint_compressed = meta & 0x20 != 0;

        let (height_flat, raw_outpoint) = if outpoint_compressed {
            let offset = read_u32_varint(&mut reader)?;
            let flat = read_u32_varint(&mut reader)?;
            let height = min_height.checked_add(offset).ok_or(CodecError::Overflow)?;
            (Some((height, flat)), None)
        } else {
            let mut txid_bytes = [0_u8; 32];
            txid_bytes.copy_from_slice(reader.take(32)?);
            let vout = read_u32_compact_size(&mut reader)?;
            let outpoint = OutPoint::new(
                Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(&txid_bytes)),
                vout,
            );
            (None, Some(outpoint))
        };

        let signature = if sig_compressed {
            let mut sig = [0_u8; 64];
            sig.copy_from_slice(reader.take(64)?);
            let pubkey_hash = if pkh_present {
                let mut hash = [0_u8; 20];
                hash.copy_from_slice(reader.take(20)?);
                Some(hash)
            } else {
                None
            };
            let hash_type = if standard {
                None
            } else {
                Some(reader.read_u8()?)
            };
            SigParts::Compressed {
                sig,
                pubkey_hash,
                hash_type,
                standard,
            }
        } else {
            let script_sig = reader.read_vlp()?.to_vec();
            let witness_count = reader.read_varint_capped(5)?;
            let witness_count = usize::try_from(witness_count).map_err(|_| CodecError::Overflow)?;
            if witness_count > reader.remaining() {
                return Err(CodecError::Truncated);
            }
            let mut witness = Vec::with_capacity(witness_count);
            for _ in 0..witness_count {
                witness.push(reader.read_vlp()?.to_vec());
            }
            SigParts::Uncompressed {
                script_sig,
                witness,
            }
        };
        let sequence = sequence_value(seq_code, &mut reader)?;

        parsed.push(ParsedInput {
            height_flat,
            raw_outpoint,
            sequence,
            signature,
        });
    }

    let mut located = resolve_outpoints_grouped(&parsed, &mut *resolver)?;

    let mut inputs: Vec<InputParts> = Vec::with_capacity(input_count);
    for (index, part) in parsed.into_iter().enumerate() {
        if index % CANCELLATION_POLL_INPUTS == 0 && resolver.cancelled() {
            return Err(CodecError::Cancelled);
        }
        let ParsedInput {
            height_flat,
            raw_outpoint,
            sequence,
            signature,
        } = part;
        let sig_compressed = matches!(signature, SigParts::Compressed { .. });
        let (outpoint, resolved) = match height_flat {
            Some((height, _)) => match located[index].take() {
                Some(Ok(Some(found))) => (found.0, Some(found.1)),
                Some(Ok(None)) | None => return Err(CodecError::BodyMissing(height)),
                Some(Err(error)) => {
                    return Err(lookup_failure(error, CodecError::BodyMissing(height)));
                }
            },
            None => match raw_outpoint {
                Some(outpoint) => (outpoint, None),
                None => return Err(CodecError::Truncated),
            },
        };
        let resolved = if sig_compressed {
            resolve_sig_prevout(&mut *resolver, &outpoint, resolved)?
        } else {
            resolved
        };

        inputs.push(InputParts {
            outpoint,
            resolved,
            sequence,
            signature,
        });
    }

    let mut outputs: Vec<TxOut> = Vec::with_capacity(output_count);
    for index in 0..output_count {
        let code = *output_meta.get(index).ok_or(CodecError::Truncated)?;
        let script = match code {
            0 => reader.read_vlp()?.to_vec(),
            1 => output_script(1, reader.take(65)?)?,
            2 => output_script(2, reader.take(33)?)?,
            3 => output_script(3, reader.take(20)?)?,
            4 => output_script(4, reader.take(20)?)?,
            5 => output_script(5, reader.take(20)?)?,
            6 => output_script(6, reader.take(32)?)?,
            7 => output_script(7, reader.take(32)?)?,
            _ => return Err(CodecError::NonCanonical),
        };
        let amount = reader.read_varint()?;
        outputs.push(TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: Script::from_bytes(script),
        });
    }

    if reader.remaining() != 0 {
        return Err(CodecError::NonCanonical);
    }

    let tx = Tx {
        version,
        inputs: inputs
            .iter()
            .map(|part| TxIn {
                previous_output: part.outpoint,
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(part.sequence),
                witness: Witness::new(),
            })
            .collect(),
        outputs,
        lock_time: LockTime::from_consensus(locktime),
    };
    Ok(DecompressPlan { tx, inputs })
}

pub(crate) fn decompress_finalize(
    plan: DecompressPlan,
    resolver: &dyn PrevoutResolver,
) -> Result<Tx, CodecError> {
    let DecompressPlan { mut tx, inputs } = plan;
    let cache = SighashCache::new(&tx);
    let mut fills: Vec<(Script, Witness)> = Vec::with_capacity(inputs.len());
    for (index, part) in inputs.iter().enumerate() {
        if index % CANCELLATION_POLL_INPUTS == 0 && resolver.cancelled() {
            return Err(CodecError::Cancelled);
        }
        let fill = match &part.signature {
            SigParts::Uncompressed {
                script_sig,
                witness,
            } => (
                Script::from_bytes(script_sig.clone()),
                Witness::from_stack(witness.clone()),
            ),
            SigParts::Compressed {
                sig,
                pubkey_hash,
                hash_type,
                standard,
            } => {
                let prevout = part
                    .resolved
                    .as_ref()
                    .ok_or(CodecError::PrevoutMissing(part.outpoint))?;
                let kind = prevout_kind(prevout.txout.script_pubkey.as_bytes());
                match kind {
                    PrevoutKind::P2tr => {
                        if pubkey_hash.is_some() {
                            return Err(CodecError::UnsupportedScript);
                        }
                        let mut item = sig.to_vec();
                        if !standard {
                            item.push(hash_type.ok_or(CodecError::NonCanonical)?);
                        }
                        (Script::new(), Witness::from_stack(vec![item]))
                    }
                    PrevoutKind::P2pkh(_) | PrevoutKind::P2wpkh(_) | PrevoutKind::P2sh(_) => {
                        let hash_type_byte = if *standard {
                            1_u8
                        } else {
                            hash_type.ok_or(CodecError::NonCanonical)?
                        };
                        let public = recover_pubkey(
                            &cache,
                            &Recovery {
                                index,
                                sig,
                                hash_type: hash_type_byte,
                                kind: &kind,
                                prevout,
                                stored_pkh: pubkey_hash.as_ref(),
                            },
                        )?;
                        let mut sig_item = der_encode(sig);
                        sig_item.push(hash_type_byte);
                        match kind {
                            PrevoutKind::P2pkh(_) => {
                                let mut script_sig = push_data(&sig_item);
                                script_sig.extend_from_slice(&push_data(&public));
                                (Script::from_bytes(script_sig), Witness::new())
                            }
                            PrevoutKind::P2wpkh(_) => {
                                (Script::new(), Witness::from_stack(vec![sig_item, public]))
                            }
                            PrevoutKind::P2sh(script_hash) => {
                                let redeem_hash =
                                    pubkey_hash.ok_or(CodecError::UnsupportedScript)?;
                                let mut redeem = Vec::with_capacity(22);
                                redeem.extend_from_slice(&[0x00, 0x14]);
                                redeem.extend_from_slice(&redeem_hash);
                                if hash160_20(&redeem) != script_hash {
                                    return Err(CodecError::UnsupportedScript);
                                }
                                (
                                    Script::from_bytes(push_data(&redeem)),
                                    Witness::from_stack(vec![sig_item, public]),
                                )
                            }
                            PrevoutKind::P2wsh | PrevoutKind::P2tr | PrevoutKind::Other => {
                                return Err(CodecError::UnsupportedScript);
                            }
                        }
                    }
                    PrevoutKind::P2wsh | PrevoutKind::Other => {
                        return Err(CodecError::UnsupportedScript);
                    }
                }
            }
        };
        fills.push(fill);
    }
    for (input, (script_sig, witness)) in tx.inputs.iter_mut().zip(fills) {
        input.script_sig = script_sig;
        input.witness = witness;
    }

    if consensus_bytes(&tx).len() > MAX_COMPRESSED_TX_BYTES {
        return Err(CodecError::Overflow);
    }
    Ok(tx)
}

#[cfg(test)]
pub(crate) fn decompress_transaction(
    bytes: &[u8],
    resolver: &mut dyn PrevoutResolver,
) -> Result<Tx, CodecError> {
    let plan = decompress_prepare(bytes, resolver)?;
    decompress_finalize(plan, resolver)
}

#[cfg(test)]
mod tests;
