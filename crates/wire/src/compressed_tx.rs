use bitcoin::hashes::{Hash as _, hash160};
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin_rs_consensus::primitives::{
    Amount, LockTime, OutPoint, Script, Sequence, SighashCache, Tx, TxIn, TxOut, Txid, Witness,
    consensus_bytes, varint,
};
use bitcoin_rs_consensus::script::push_data;
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
    #[error("coin set could not be read")]
    CoinReadFailed,
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
    #[error("coin set could not be read")]
    CoinReadFailed,
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
            CodecError::CoinReadFailed => {
                Self::Misc("coin set could not be read; retry".to_owned())
            }
        }
    }
}

fn lookup_failure(error: LookupError, missing: CodecError) -> CodecError {
    match error {
        LookupError::Missing => missing,
        LookupError::BodyMissing(height) => CodecError::BodyMissing(height),
        LookupError::CorruptBody(height) => CodecError::CorruptBody(height),
        LookupError::BodyReadFailed(height) => CodecError::BodyReadFailed(height),
        LookupError::CoinReadFailed => CodecError::CoinReadFailed,
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
        (OutputShape::P2pkh, payload) =>
        {
            #[expect(clippy::expect_used, reason = "P2pkh payload shape is 20 bytes")]
            PrevoutKind::P2pkh(payload.try_into().expect("P2pkh payload shape is 20 bytes"))
        }
        (OutputShape::P2sh, payload) =>
        {
            #[expect(clippy::expect_used, reason = "P2sh payload shape is 20 bytes")]
            PrevoutKind::P2sh(payload.try_into().expect("P2sh payload shape is 20 bytes"))
        }
        (OutputShape::P2wpkh, payload) =>
        {
            #[expect(clippy::expect_used, reason = "P2wpkh payload shape is 20 bytes")]
            PrevoutKind::P2wpkh(
                payload
                    .try_into()
                    .expect("P2wpkh payload shape is 20 bytes"),
            )
        }
        (OutputShape::P2wsh, _) => PrevoutKind::P2wsh,
        (OutputShape::P2tr, _) => PrevoutKind::P2tr,
        _ => PrevoutKind::Other,
    }
}

fn hash160_20(data: &[u8]) -> [u8; 20] {
    *hash160::Hash::hash(data).as_byte_array()
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
    #[expect(clippy::expect_used, reason = "DER sequence length fits in u8")]
    der.push(u8::try_from(r.len() + s.len() + 4).expect("DER sequence length fits in u8"));
    der.push(0x02);
    #[expect(clippy::expect_used, reason = "DER integer r length fits in u8")]
    der.push(u8::try_from(r.len()).expect("DER integer r length fits in u8"));
    der.extend_from_slice(&r);
    der.push(0x02);
    #[expect(clippy::expect_used, reason = "DER integer s length fits in u8")]
    der.push(u8::try_from(s.len()).expect("DER integer s length fits in u8"));
    der.extend_from_slice(&s);
    der
}

struct CompressedSig {
    sig: [u8; 64],
    pubkey_hash: Option<[u8; 20]>,
    hash_type: Option<u8>,
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

fn compress_p2tr_signature(input: &TxIn) -> Option<CompressedSig> {
    if !input.script_sig.is_empty() || input.witness.len() != 1 {
        return None;
    }
    let item = input.witness.first()?;
    match item.len() {
        64 => {
            #[expect(clippy::expect_used, reason = "item slice length is exactly 64")]
            let sig = item.try_into().expect("item slice length is exactly 64");
            Some(CompressedSig {
                sig,
                pubkey_hash: None,
                hash_type: None,
                standard: true,
            })
        }
        65 => {
            let (sig, hash_type) = item.split_at(64);
            #[expect(clippy::expect_used, reason = "split_at(64) produces 64-byte slice")]
            let sig = sig.try_into().expect("split_at(64) produces 64-byte slice");
            Some(CompressedSig {
                sig,
                pubkey_hash: None,
                hash_type: Some(*hash_type.first()?),
                standard: false,
            })
        }
        _ => None,
    }
}

fn compress_p2pkh_signature(input: &TxIn, expected: &[u8; 20]) -> Option<CompressedSig> {
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

fn compress_p2wpkh_signature(input: &TxIn, expected: &[u8; 20]) -> Option<CompressedSig> {
    if !input.script_sig.is_empty() || input.witness.len() != 2 {
        return None;
    }
    let pubkey = input.witness.get(1)?;
    if pubkey.len() != 33 || hash160_20(pubkey) != *expected {
        return None;
    }
    ecdsa_compressed(input.witness.first()?)
}

fn compress_p2sh_signature(input: &TxIn, script_hash: &[u8; 20]) -> Option<CompressedSig> {
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
    #[expect(clippy::expect_used, reason = "slice 3..23 has length 20")]
    let redeem_hash: [u8; 20] = script_sig[3..23]
        .try_into()
        .expect("slice 3..23 has length 20");
    if hash160_20(pubkey) != redeem_hash || hash160_20(&script_sig[1..]) != *script_hash {
        return None;
    }
    let mut compressed = ecdsa_compressed(input.witness.first()?)?;
    compressed.pubkey_hash = Some(redeem_hash);
    Some(compressed)
}

fn compressed_signature(input: &TxIn, kind: &PrevoutKind) -> Option<CompressedSig> {
    match kind {
        PrevoutKind::P2tr => compress_p2tr_signature(input),
        PrevoutKind::P2pkh(expected) => compress_p2pkh_signature(input, expected),
        PrevoutKind::P2wpkh(expected) => compress_p2wpkh_signature(input, expected),
        PrevoutKind::P2sh(script_hash) => compress_p2sh_signature(input, script_hash),
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

    let (resolved, degraded) = resolve_inputs_prevouts(tx, resolver)?;
    let min_height = compute_min_height(tx, &resolved, options.compress_outpoints);
    let flat_results = if options.compress_outpoints {
        let (order, members) = flat_lookup_groups(tx, &resolved, &degraded);
        resolve_flats_grouped(tx, resolver, &order, &members)?
    } else {
        vec![None; tx.inputs.len()]
    };

    let (plans, warnings) = build_compression_plans(
        tx,
        &resolved,
        &degraded,
        &flat_results,
        min_height,
        options.compress_outpoints,
    )?;
    let bytes = write_compressed_transaction(tx, &plans, min_height)?;
    Ok((bytes, warnings))
}

type ResolvedInputs = (Vec<Option<ResolvedPrevout>>, Vec<Option<String>>);

fn resolve_inputs_prevouts(
    tx: &Tx,
    resolver: &mut dyn PrevoutResolver,
) -> Result<ResolvedInputs, CodecError> {
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
                    LookupError::CoinReadFailed => "prevout coin could not be read".to_owned(),
                    LookupError::LimitExceeded(_) | LookupError::Cancelled => {
                        "prevout context is unavailable".to_owned()
                    }
                };
                degraded.push(Some(reason));
                resolved.push(None);
            }
        }
    }
    Ok((resolved, degraded))
}

fn compute_min_height(
    tx: &Tx,
    resolved: &[Option<ResolvedPrevout>],
    compress_outpoints: bool,
) -> u32 {
    let locktime = tx.lock_time.to_consensus();
    let mut min_height: Option<u32> = if locktime != 0 {
        Some(locktime - 1)
    } else {
        None
    };
    if compress_outpoints {
        for prevout in resolved.iter().flatten() {
            if let Some(height) = prevout.confirmed_height {
                let candidate = height.saturating_sub(1);
                min_height = Some(min_height.map_or(candidate, |m: u32| m.min(candidate)));
            }
        }
    }
    min_height.unwrap_or(0)
}

fn build_compression_plans(
    tx: &Tx,
    resolved: &[Option<ResolvedPrevout>],
    degraded: &[Option<String>],
    flat_results: &[Option<Result<Option<u32>, LookupError>>],
    min_height: u32,
    compress_outpoints: bool,
) -> Result<(Vec<Plan>, Vec<String>), CodecError> {
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
        if compress_outpoints {
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
                        Some(Err(LookupError::CoinReadFailed)) => {
                            Some("prevout coin could not be read".to_owned())
                        }
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
    Ok((plans, warnings))
}

fn write_compressed_transaction(
    tx: &Tx,
    plans: &[Plan],
    min_height: u32,
) -> Result<Vec<u8>, CodecError> {
    let flag = |value: u32| -> u8 {
        if (1..=3).contains(&value) {
            u8::try_from(value).unwrap_or(0)
        } else {
            0
        }
    };
    let input_count = u32::try_from(tx.inputs.len()).map_err(|_| CodecError::Overflow)?;
    let output_count = u32::try_from(tx.outputs.len()).map_err(|_| CodecError::Overflow)?;
    let locktime = tx.lock_time.to_consensus();
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
    for plan in plans {
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

    write_compressed_inputs(&mut writer, tx, plans)?;
    write_compressed_outputs(&mut writer, tx)?;
    Ok(writer.bytes)
}

fn write_compressed_inputs(writer: &mut Writer, tx: &Tx, plans: &[Plan]) -> Result<(), CodecError> {
    for (input, plan) in tx.inputs.iter().zip(plans.iter()) {
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
    Ok(())
}

fn write_compressed_outputs(writer: &mut Writer, tx: &Tx) -> Result<(), CodecError> {
    for output in &tx.outputs {
        let (shape, payload) = output_shape(output.script_pubkey.as_bytes());
        if shape == OutputShape::Custom {
            writer.write_vlp(payload)?;
        } else {
            writer.write(payload)?;
        }
        writer.write_varint(output.value.to_sat())?;
    }
    Ok(())
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

pub(crate) fn decompress_prepare(
    bytes: &[u8],
    resolver: &mut dyn PrevoutResolver,
) -> Result<DecompressPlan, CodecError> {
    if bytes.len() > MAX_COMPRESSED_TX_BYTES {
        return Err(CodecError::Overflow);
    }
    let mut reader = Reader::new(bytes);
    let header = parse_decompress_header(&mut reader)?;
    let parsed =
        parse_decompress_inputs(&mut reader, &header.input_meta, header.min_height, resolver)?;
    let inputs = resolve_decompress_inputs(parsed, resolver)?;
    let outputs = parse_decompress_outputs(&mut reader, &header.output_meta)?;

    if reader.remaining() != 0 {
        return Err(CodecError::NonCanonical);
    }

    let tx = Tx {
        version: header.version,
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
        lock_time: LockTime::from_consensus(header.locktime),
    };
    Ok(DecompressPlan { tx, inputs })
}

struct DecompressHeader {
    version: u32,
    locktime: u32,
    min_height: u32,
    input_meta: Vec<u8>,
    output_meta: Vec<u8>,
}

fn parse_decompress_header(reader: &mut Reader<'_>) -> Result<DecompressHeader, CodecError> {
    let metadata = reader.read_u8()?;
    let version_flag = metadata & 0x03;
    let input_flag = (metadata >> 2) & 0x03;
    let output_flag = (metadata >> 4) & 0x03;
    let has_locktime = metadata & 0x40 != 0;
    let has_min_height = metadata & 0x80 != 0;

    let version = if version_flag == 0 {
        read_u32_compact_size(reader)?
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
        read_u32_varint(reader)?
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

    let (input_meta, output_meta) = decode_bits(reader, input_count, output_count)?;
    Ok(DecompressHeader {
        version,
        locktime,
        min_height,
        input_meta,
        output_meta,
    })
}

fn parse_decompress_inputs(
    reader: &mut Reader<'_>,
    input_meta: &[u8],
    min_height: u32,
    resolver: &dyn PrevoutResolver,
) -> Result<Vec<ParsedInput>, CodecError> {
    let mut parsed: Vec<ParsedInput> = Vec::with_capacity(input_meta.len());
    for (index, &meta) in input_meta.iter().enumerate() {
        if index % CANCELLATION_POLL_INPUTS == 0 && resolver.cancelled() {
            return Err(CodecError::Cancelled);
        }
        let sig_compressed = meta & 1 != 0;
        let pkh_present = meta & 0x02 != 0;
        let standard = meta & 0x04 != 0;
        let seq_code = (meta >> 3) & 0x03;
        let outpoint_compressed = meta & 0x20 != 0;

        let (height_flat, raw_outpoint) =
            read_input_outpoint(reader, outpoint_compressed, min_height)?;

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
        let sequence = sequence_value(seq_code, reader)?;

        parsed.push(ParsedInput {
            height_flat,
            raw_outpoint,
            sequence,
            signature,
        });
    }
    Ok(parsed)
}

type InputOutpointResult = (Option<(u32, u32)>, Option<OutPoint>);

fn read_input_outpoint(
    reader: &mut Reader<'_>,
    outpoint_compressed: bool,
    min_height: u32,
) -> Result<InputOutpointResult, CodecError> {
    if outpoint_compressed {
        let offset = read_u32_varint(reader)?;
        let flat = read_u32_varint(reader)?;
        let height = min_height.checked_add(offset).ok_or(CodecError::Overflow)?;
        Ok((Some((height, flat)), None))
    } else {
        let mut txid_bytes = [0_u8; 32];
        txid_bytes.copy_from_slice(reader.take(32)?);
        let vout = read_u32_compact_size(reader)?;
        let outpoint = OutPoint::new(
            Txid(bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                &txid_bytes,
            )),
            vout,
        );
        Ok((None, Some(outpoint)))
    }
}

fn resolve_decompress_inputs(
    parsed: Vec<ParsedInput>,
    resolver: &mut dyn PrevoutResolver,
) -> Result<Vec<InputParts>, CodecError> {
    let mut located = resolve_outpoints_grouped(&parsed, resolver)?;
    let mut inputs: Vec<InputParts> = Vec::with_capacity(parsed.len());
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
            resolve_sig_prevout(resolver, &outpoint, resolved)?
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
    Ok(inputs)
}

fn parse_decompress_outputs(
    reader: &mut Reader<'_>,
    output_meta: &[u8],
) -> Result<Vec<TxOut>, CodecError> {
    let mut outputs: Vec<TxOut> = Vec::with_capacity(output_meta.len());
    for &code in output_meta {
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
    Ok(outputs)
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
        let fill = finalize_input_signature(index, part, &cache)?;
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

fn finalize_input_signature(
    index: usize,
    part: &InputParts,
    cache: &SighashCache<'_>,
) -> Result<(Script, Witness), CodecError> {
    match &part.signature {
        SigParts::Uncompressed {
            script_sig,
            witness,
        } => Ok((
            Script::from_bytes(script_sig.clone()),
            Witness::from_stack(witness.clone()),
        )),
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
                    Ok((Script::new(), Witness::from_stack(vec![item])))
                }
                PrevoutKind::P2pkh(_) | PrevoutKind::P2wpkh(_) | PrevoutKind::P2sh(_) => {
                    let hash_type_byte = if *standard {
                        1_u8
                    } else {
                        hash_type.ok_or(CodecError::NonCanonical)?
                    };
                    let recovery = Recovery {
                        index,
                        sig,
                        hash_type: hash_type_byte,
                        kind: &kind,
                        prevout,
                        stored_pkh: pubkey_hash.as_ref(),
                    };
                    recover_and_build_legacy_witness(&recovery, cache)
                }
                PrevoutKind::P2wsh | PrevoutKind::Other => Err(CodecError::UnsupportedScript),
            }
        }
    }
}

fn recover_and_build_legacy_witness(
    recovery: &Recovery<'_>,
    cache: &SighashCache<'_>,
) -> Result<(Script, Witness), CodecError> {
    let public = recover_pubkey(cache, recovery)?;
    let mut sig_item = der_encode(recovery.sig);
    sig_item.push(recovery.hash_type);
    match recovery.kind {
        PrevoutKind::P2pkh(_) => {
            let mut script_sig = push_data(&sig_item);
            script_sig.extend_from_slice(&push_data(&public));
            Ok((Script::from_bytes(script_sig), Witness::new()))
        }
        PrevoutKind::P2wpkh(_) => Ok((Script::new(), Witness::from_stack(vec![sig_item, public]))),
        PrevoutKind::P2sh(script_hash) => {
            let redeem_hash = recovery.stored_pkh.ok_or(CodecError::UnsupportedScript)?;
            let mut redeem = Vec::with_capacity(22);
            redeem.extend_from_slice(&[0x00, 0x14]);
            redeem.extend_from_slice(redeem_hash);
            if hash160_20(&redeem) != *script_hash {
                return Err(CodecError::UnsupportedScript);
            }
            Ok((
                Script::from_bytes(push_data(&redeem)),
                Witness::from_stack(vec![sig_item, public]),
            ))
        }
        PrevoutKind::P2wsh | PrevoutKind::P2tr | PrevoutKind::Other => {
            Err(CodecError::UnsupportedScript)
        }
    }
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
mod tests {
    #![expect(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "test assertions fail with the checked value in the message"
    )]

    use std::collections::HashMap;
    use std::str::FromStr as _;

    use bitcoin::hex::FromHex as _;
    use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Sighash, SighashCache, Tx, TxIn,
        TxOut, Txid, Witness, consensus_bytes, deserialize, layout::ParsedBlock,
    };
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

    use super::{
        CodecError, CompressOptions, LookupError, ResolvedPrevout, compress_transaction,
        decompress_transaction, encode_bits, write_varint,
    };
    use crate::compressed_tx::PrevoutResolver;

    const FIXTURE: &str = include_str!("../../../testdata/serving/bip337_vectors.json");

    #[derive(Default)]
    struct MapResolver {
        prevouts: HashMap<OutPoint, ResolvedPrevout>,
        flats: HashMap<(u32, Txid, u32), u32>,
        at: HashMap<(u32, u32), (OutPoint, ResolvedPrevout)>,
        cancelled: bool,
    }

    impl MapResolver {
        fn register(&mut self, height: u32, txid: Txid, vout: u32, first_flat: u32, txout: TxOut) {
            let outpoint = OutPoint::new(txid, vout);
            let resolved = ResolvedPrevout {
                txout,
                confirmed_height: Some(height),
            };
            self.prevouts.insert(outpoint, resolved.clone());
            self.flats.insert((height, txid, vout), first_flat + vout);
            self.at
                .insert((height, first_flat + vout), (outpoint, resolved));
        }

        fn register_tx(&mut self, height: u32, tx: &Tx, first_flat: u32) {
            for (vout, output) in tx.outputs.iter().enumerate() {
                let vout = u32::try_from(vout).unwrap();
                self.register(height, tx.txid(), vout, first_flat, output.clone());
            }
        }
    }

    impl PrevoutResolver for MapResolver {
        fn prevout(&mut self, outpoint: &OutPoint) -> Result<Option<ResolvedPrevout>, LookupError> {
            Ok(self.prevouts.get(outpoint).cloned())
        }

        fn flat_output_index(
            &mut self,
            height: u32,
            txid: &Txid,
            vout: u32,
        ) -> Result<Option<u32>, LookupError> {
            Ok(self.flats.get(&(height, *txid, vout)).copied())
        }

        fn outpoint_at(
            &mut self,
            height: u32,
            flat_index: u32,
        ) -> Result<Option<(OutPoint, ResolvedPrevout)>, LookupError> {
            Ok(self.at.get(&(height, flat_index)).cloned())
        }

        fn cancelled(&self) -> bool {
            self.cancelled
        }
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        Vec::<u8>::from_hex(text).unwrap()
    }

    fn fixture_vectors() -> Vec<Value> {
        let parsed: Value = sonic_rs::from_str(FIXTURE).unwrap();
        parsed
            .get("vectors")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .cloned()
            .collect()
    }

    fn fixture_resolver(vector: &Value) -> MapResolver {
        let mut resolver = MapResolver::default();
        for input in vector.get("inputs").and_then(Value::as_array).unwrap() {
            let txid =
                Txid::from_str(input.get("prevout_txid").and_then(Value::as_str).unwrap()).unwrap();
            let vout = u32::try_from(input.get("vout").and_then(Value::as_u64).unwrap()).unwrap();
            let height =
                u32::try_from(input.get("height").and_then(Value::as_u64).unwrap()).unwrap();
            let flat = u32::try_from(
                input
                    .get("flat_output_index")
                    .and_then(Value::as_u64)
                    .unwrap(),
            )
            .unwrap();
            let txout = TxOut {
                value: Amount::from_sat(input.get("value_sats").and_then(Value::as_u64).unwrap()),
                script_pubkey: Script::from_bytes(hex_bytes(
                    input
                        .get("prevout_script_hex")
                        .and_then(Value::as_str)
                        .unwrap(),
                )),
            };
            resolver.register(height, txid, vout, flat - vout, txout);
        }
        resolver
    }

    #[test]
    fn varint_uses_core_carry_form() {
        let mut encoded = Vec::new();
        write_varint(5000, &mut encoded).unwrap();
        assert_eq!(encoded, [0xa6, 0x08]);
        let mut reader = super::Reader::new(&encoded);
        assert_eq!(super::Reader::read_varint(&mut reader).unwrap(), 5000);
        for value in [
            0_u64,
            1,
            127,
            128,
            16_511,
            4_294_967_293,
            1_u64 << 40,
            2_100_000_000_000_000,
            u64::MAX,
        ] {
            let mut encoded = Vec::new();
            write_varint(value, &mut encoded).unwrap();
            let mut reader = super::Reader::new(&encoded);
            assert_eq!(reader.read_varint().unwrap(), value);
        }
        let mut encoded = Vec::new();
        write_varint(u64::MAX, &mut encoded).unwrap();
        assert_eq!(encoded.len(), 10);
        let mut reader = super::Reader::new(&encoded);
        assert_eq!(reader.read_varint().unwrap(), u64::MAX);
        let mut encoded = Vec::new();
        write_varint(1_u64 << 40, &mut encoded).unwrap();
        assert_eq!(encoded.len(), 6);
        let mut reader = super::Reader::new(&encoded);
        assert_eq!(reader.read_varint().unwrap(), 1_u64 << 40);
        let mut reader = super::Reader::new(&encoded);
        assert_eq!(
            super::read_u32_varint(&mut reader),
            Err(CodecError::Overflow)
        );
        let unterminated = [0x80; 11];
        let mut reader = super::Reader::new(&unterminated);
        assert_eq!(reader.read_varint(), Err(CodecError::Overflow));
    }

    #[test]
    fn encode_bits_matches_published_example() {
        assert_eq!(encode_bits(&[37], &[5]), [0x96, 0x80]);
    }

    #[test]
    fn handlers_gate_on_the_runtime_opt_in() {
        use std::sync::Arc;

        use sonic_rs::json;

        use crate::context::{Context, ContextHandles};
        use crate::handlers::Handler;

        let tx = funding_tx(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2wpkh_script([1_u8; 20]),
        });
        let raw_hex = bitcoin::hex::DisplayHex::to_lower_hex_string(&consensus_bytes(&tx));

        let disabled = Handler::new(Arc::new(Context::new()));
        for method in ["compressrawtransaction", "decompressrawtransaction"] {
            let error = disabled.dispatch(method, &json!([raw_hex])).unwrap_err();
            assert!(
                matches!(error, crate::RpcError::MethodDisabled(_)),
                "{method}: {error:?}"
            );
            assert_eq!(error.code(), -32603, "{method} must never answer -32601");
        }

        let enabled = Handler::new(Arc::new(Context::from_handles(ContextHandles {
            compressed_transactions: true,
            ..ContextHandles::default()
        })));
        let compressed = enabled
            .dispatch("compressrawtransaction", &json!([raw_hex]))
            .unwrap();
        let compressed_hex = compressed
            .get("result")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        assert_eq!(
            compressed
                .get("warnings")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            1
        );
        let restored = enabled
            .dispatch("decompressrawtransaction", &json!([compressed_hex]))
            .unwrap();
        assert_eq!(restored.as_str().unwrap(), raw_hex);
        let oversize = "00".repeat(super::MAX_COMPRESSED_TX_BYTES + 1);
        let error = enabled
            .dispatch("compressrawtransaction", &json!([oversize]))
            .unwrap_err();
        assert_eq!(error.code(), -8);
    }

    #[test]
    fn codec_error_wire_matrix() {
        use super::Limit;
        use crate::RpcError;

        for (error, code) in [
            (CodecError::Truncated, -22),
            (CodecError::NonCanonical, -22),
            (CodecError::EmptyTransaction, -22),
            (CodecError::UnsupportedScript, -22),
            (CodecError::Sighash, -22),
            (CodecError::SignatureUnrecoverable, -22),
            (CodecError::Overflow, -8),
            (CodecError::LimitExceeded(Limit::State), -1),
            (CodecError::Cancelled, -1),
            (
                CodecError::PrevoutMissing(OutPoint::new(
                    Txid(Hash256::from_le_bytes(&[1_u8; 32])),
                    0,
                )),
                -5,
            ),
            (CodecError::BodyMissing(7), -1),
            (CodecError::CorruptBody(7), -1),
            (CodecError::BodyReadFailed(7), -1),
            (CodecError::CoinReadFailed, -1),
        ] {
            assert_eq!(RpcError::from(error).code(), code);
        }
    }

    #[test]
    fn registry_rows_are_extensions_at_package_version() {
        for name in ["compressrawtransaction", "decompressrawtransaction"] {
            let entry = crate::manifest::MANIFEST
                .iter()
                .find(|entry| entry.name == name)
                .unwrap();
            assert_eq!(entry.status, crate::manifest::Status::Extension);
            assert_eq!(entry.feature, "");
            assert_eq!(entry.core_version, "");
            let version = |text: &str| {
                text.split('.')
                    .map(|part| part.parse::<u32>().unwrap())
                    .collect::<Vec<_>>()
            };
            assert!(
                version(entry.since) <= version(bitcoin_rs_consensus::primitives::PKG_VERSION),
                "a row cannot describe a version later than the package"
            );
        }
    }

    #[test]
    fn published_vectors_restore_byte_for_byte() {
        for vector in fixture_vectors() {
            let name = vector.get("name").and_then(Value::as_str).unwrap();
            let raw_hex = vector.get("raw_hex").and_then(Value::as_str).unwrap();
            let compressed_hex = vector
                .get("compressed_hex")
                .and_then(Value::as_str)
                .unwrap();
            let raw: Tx = deserialize(&hex_bytes(raw_hex)).unwrap();
            assert_eq!(
                raw.txid().to_string(),
                vector.get("txid").and_then(Value::as_str).unwrap(),
                "{name}"
            );
            assert_eq!(
                raw.wtxid().to_string(),
                vector.get("wtxid").and_then(Value::as_str).unwrap(),
                "{name}"
            );
            let mut resolver = fixture_resolver(&vector);
            let (compressed, warnings) = compress_transaction(
                &raw,
                &mut resolver,
                CompressOptions {
                    compress_outpoints: true,
                },
            )
            .unwrap();
            assert!(warnings.is_empty(), "{name}: {warnings:?}");
            assert_eq!(
                compressed,
                hex_bytes(compressed_hex),
                "{name}: compressed bytes differ"
            );
            let mut resolver = fixture_resolver(&vector);
            let restored = decompress_transaction(&compressed, &mut resolver).unwrap();
            assert_eq!(restored, raw, "{name}: round trip differs");
            assert_eq!(consensus_bytes(&restored), hex_bytes(raw_hex), "{name}");
        }
    }

    struct Signer {
        secp: Secp256k1<bitcoin::secp256k1::All>,
        secret: SecretKey,
        public: PublicKey,
    }

    impl Signer {
        fn new(seed: u8) -> Self {
            let secp = Secp256k1::new();
            let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
            let public = PublicKey::from_secret_key(&secp, &secret);
            Self {
                secp,
                secret,
                public,
            }
        }

        fn compressed_pubkey(&self) -> Vec<u8> {
            self.public.serialize().to_vec()
        }

        fn uncompressed_pubkey(&self) -> Vec<u8> {
            self.public.serialize_uncompressed().to_vec()
        }

        fn pubkey_hash(&self) -> [u8; 20] {
            super::hash160_20(&self.compressed_pubkey())
        }

        fn ecdsa_item(&self, digest: Hash256, high_s: bool) -> Vec<u8> {
            let message = Message::from_digest(*digest.as_byte_array());
            let signature = self.secp.sign_ecdsa(&message, &self.secret);
            let mut compact = signature.serialize_compact();
            if high_s {
                const ORDER: [u8; 32] = [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2,
                    0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
                ];
                let mut borrow = 0_i32;
                for index in (32..64).rev() {
                    let diff = i32::from(ORDER[index - 32]) - i32::from(compact[index]) - borrow;
                    if diff < 0 {
                        compact[index] = u8::try_from(diff + 256).unwrap();
                        borrow = 1;
                    } else {
                        compact[index] = u8::try_from(diff).unwrap();
                        borrow = 0;
                    }
                }
            }
            let parsed = bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact).unwrap();
            let mut item = parsed.serialize_der().to_vec();
            item.push(1);
            item
        }
    }

    fn funding_tx(output: TxOut) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x01, 0x2a]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![output],
            lock_time: LockTime::ZERO,
        }
    }

    fn spend_of(prevout: &Tx, script_sig: Script, witness: Witness) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(prevout.txid(), 0),
                script_sig,
                sequence: Sequence::from_consensus(0xffff_fffd),
                witness,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: Script::from_bytes(
                    vec![0x00, 0x14].into_iter().chain([7_u8; 20]).collect(),
                ),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn p2pkh_script(hash: [u8; 20]) -> Script {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&hash);
        script.extend_from_slice(&[0x88, 0xac]);
        Script::from_bytes(script)
    }

    fn p2wpkh_script(hash: [u8; 20]) -> Script {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&hash);
        Script::from_bytes(script)
    }

    fn roundtrip(tx: &Tx, resolver: &mut MapResolver, compress_outpoints: bool) -> Vec<u8> {
        let (compressed, _) =
            compress_transaction(tx, resolver, CompressOptions { compress_outpoints }).unwrap();
        let restored = decompress_transaction(&compressed, resolver).unwrap();
        assert_eq!(&restored, tx);
        compressed
    }

    #[test]
    fn roundtrip_legacy_p2pkh() {
        let signer = Signer::new(7);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2pkh_script(signer.pubkey_hash()),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
            .unwrap();
        let sig_item = signer.ecdsa_item(digest, false);
        let mut script_sig = super::push_data(&sig_item);
        script_sig.extend_from_slice(&super::push_data(&signer.compressed_pubkey()));
        tx.inputs[0].script_sig = Script::from_bytes(script_sig);
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 3);
        roundtrip(&tx, &mut resolver, true);
    }

    #[test]
    fn roundtrip_legacy_p2pkh_uncompressed_key() {
        let signer = Signer::new(7);
        let uncompressed = signer.uncompressed_pubkey();
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2pkh_script(super::hash160_20(&uncompressed)),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
            .unwrap();
        let sig_item = signer.ecdsa_item(digest, false);
        let mut script_sig = super::push_data(&sig_item);
        script_sig.extend_from_slice(&super::push_data(&uncompressed));
        tx.inputs[0].script_sig = Script::from_bytes(script_sig);
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 3);
        roundtrip(&tx, &mut resolver, true);
    }

    #[test]
    fn hybrid_p2pkh_key_falls_back_to_uncompressed_envelope() {
        let signer = Signer::new(7);
        let mut hybrid = signer.uncompressed_pubkey();
        hybrid[0] = 0x06;
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2pkh_script(super::hash160_20(&hybrid)),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
            .unwrap();
        let sig_item = signer.ecdsa_item(digest, false);
        let mut script_sig = super::push_data(&sig_item);
        script_sig.extend_from_slice(&super::push_data(&hybrid));
        tx.inputs[0].script_sig = Script::from_bytes(script_sig);
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 3);
        roundtrip(&tx, &mut resolver, true);
    }

    #[test]
    fn foreign_p2pkh_key_falls_back_instead_of_changing_signer() {
        let signer = Signer::new(7);
        let stranger = Signer::new(19);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2pkh_script(signer.pubkey_hash()),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
            .unwrap();
        let sig_item = signer.ecdsa_item(digest, false);
        let mut script_sig = super::push_data(&sig_item);
        script_sig.extend_from_slice(&super::push_data(&stranger.compressed_pubkey()));
        tx.inputs[0].script_sig = Script::from_bytes(script_sig);
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 3);
        roundtrip(&tx, &mut resolver, true);
    }

    #[test]
    fn lossy_input_shapes_fall_back_to_uncompressed_envelope() {
        let signer = Signer::new(7);
        let stranger = Signer::new(19);

        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2pkh_script(signer.pubkey_hash()),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
            .unwrap();
        let sig_item = signer.ecdsa_item(digest, false);
        let mut script_sig = super::push_data(&sig_item);
        script_sig.extend_from_slice(&super::push_data(&signer.compressed_pubkey()));
        tx.inputs[0].script_sig = Script::from_bytes(script_sig);
        tx.inputs[0].witness = Witness::from_stack(vec![vec![0x2a]]);
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 3);
        roundtrip(&tx, &mut resolver, true);

        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2wpkh_script(signer.pubkey_hash()),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .segwit_v0_signature_hash_raw(
                0,
                p2pkh_script(signer.pubkey_hash()).as_bytes(),
                prevout.value,
                1,
            )
            .unwrap();
        let sig_item = signer.ecdsa_item(digest, false);
        tx.inputs[0].witness = Witness::from_stack(vec![sig_item, stranger.compressed_pubkey()]);
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 0);
        roundtrip(&tx, &mut resolver, true);

        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&[3_u8; 32]);
        let prev_tx = funding_tx(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(script),
        });
        let tx = spend_of(
            &prev_tx,
            Script::from_bytes(vec![0x01, 0x2a]),
            Witness::from_stack(vec![vec![4_u8; 64]]),
        );
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 0);
        roundtrip(&tx, &mut resolver, true);
    }

    #[test]
    fn nonminimal_p2pkh_pushes_fall_back_to_uncompressed_envelope() {
        fn pushdata1(data: &[u8]) -> Vec<u8> {
            let mut out = vec![0x4c, u8::try_from(data.len()).unwrap()];
            out.extend_from_slice(data);
            out
        }

        fn pushdata2(data: &[u8]) -> Vec<u8> {
            let len = u16::try_from(data.len()).unwrap().to_le_bytes();
            let mut out = vec![0x4d, len[0], len[1]];
            out.extend_from_slice(data);
            out
        }

        let signer = Signer::new(7);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2pkh_script(signer.pubkey_hash()),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut canonical = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&canonical)
            .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
            .unwrap();
        let sig_item = signer.ecdsa_item(digest, false);
        let pubkey = signer.compressed_pubkey();
        let mut script_sig = super::push_data(&sig_item);
        script_sig.extend_from_slice(&super::push_data(&pubkey));
        canonical.inputs[0].script_sig = Script::from_bytes(script_sig);
        let kind = super::prevout_kind(prevout.script_pubkey.as_bytes());
        assert!(
            super::compressed_signature(&canonical.inputs[0], &kind).is_some(),
            "canonical P2PKH pushes must take the compressed path"
        );
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 3);
        roundtrip(&canonical, &mut resolver, true);

        for script_sig in [
            {
                let mut raw = pushdata1(&sig_item);
                raw.extend_from_slice(&pushdata1(&pubkey));
                raw
            },
            {
                let mut raw = pushdata2(&sig_item);
                raw.extend_from_slice(&pushdata2(&pubkey));
                raw
            },
            {
                let mut raw = pushdata1(&sig_item);
                raw.extend_from_slice(&super::push_data(&pubkey));
                raw
            },
        ] {
            let tx = spend_of(&prev_tx, Script::from_bytes(script_sig), Witness::new());
            let kind = super::prevout_kind(prevout.script_pubkey.as_bytes());
            assert!(
                super::compressed_signature(&tx.inputs[0], &kind).is_none(),
                "non-minimal P2PKH pushes must fall back to the uncompressed envelope"
            );
            let mut resolver = MapResolver::default();
            resolver.register_tx(100, &prev_tx, 3);
            roundtrip(&tx, &mut resolver, true);
        }
    }
    #[test]
    fn p2pkh_push_exceeding_u16_does_not_panic() {
        let signer = Signer::new(42);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2pkh_script(signer.pubkey_hash()),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut oversized_sig = vec![0x4e];
        oversized_sig.extend_from_slice(&70_000_u32.to_le_bytes());
        oversized_sig.extend(std::iter::repeat_n(0x01_u8, 70_000));
        oversized_sig.push(0x00);
        let tx = spend_of(&prev_tx, Script::from_bytes(oversized_sig), Witness::new());
        let kind = super::prevout_kind(prevout.script_pubkey.as_bytes());
        let sig = super::compressed_signature(&tx.inputs[0], &kind);
        assert!(sig.is_none());
    }

    #[test]
    fn decompress_prepare_finalize_matches_single_pass() {
        let signer = Signer::new(23);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2pkh_script(signer.pubkey_hash()),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
            .unwrap();
        let sig_item = signer.ecdsa_item(digest, false);
        let mut script_sig = super::push_data(&sig_item);
        script_sig.extend_from_slice(&super::push_data(&signer.compressed_pubkey()));
        tx.inputs[0].script_sig = Script::from_bytes(script_sig);
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 3);
        let (compressed, _) = compress_transaction(
            &tx,
            &mut resolver,
            CompressOptions {
                compress_outpoints: true,
            },
        )
        .unwrap();
        let plan = super::decompress_prepare(&compressed, &mut resolver).unwrap();
        let restored = super::decompress_finalize(plan, &resolver).unwrap();
        assert_eq!(&restored, &tx);
        assert_eq!(
            &super::decompress_transaction(&compressed, &mut resolver).unwrap(),
            &tx
        );
    }

    #[test]
    fn roundtrip_p2wpkh_including_high_s() {
        for high_s in [false, true] {
            let signer = Signer::new(9);
            let prevout = TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: p2wpkh_script(signer.pubkey_hash()),
            };
            let prev_tx = funding_tx(prevout.clone());
            let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
            let digest = SighashCache::new(&tx)
                .segwit_v0_signature_hash_raw(
                    0,
                    p2pkh_script(signer.pubkey_hash()).as_bytes(),
                    prevout.value,
                    1,
                )
                .unwrap();
            let sig_item = signer.ecdsa_item(digest, high_s);
            tx.inputs[0].witness = Witness::from_stack(vec![sig_item, signer.compressed_pubkey()]);
            let mut resolver = MapResolver::default();
            resolver.register_tx(100, &prev_tx, 0);
            roundtrip(&tx, &mut resolver, true);
        }
    }

    #[test]
    fn roundtrip_nested_segwit() {
        let signer = Signer::new(11);
        let mut redeem = vec![0x00, 0x14];
        redeem.extend_from_slice(&signer.pubkey_hash());
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: {
                let mut script = vec![0xa9, 0x14];
                script.extend_from_slice(&super::hash160_20(&redeem));
                script.push(0x87);
                Script::from_bytes(script)
            },
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(
            &prev_tx,
            Script::from_bytes(super::push_data(&redeem)),
            Witness::new(),
        );
        let digest = SighashCache::new(&tx)
            .segwit_v0_signature_hash_raw(
                0,
                p2pkh_script(signer.pubkey_hash()).as_bytes(),
                prevout.value,
                1,
            )
            .unwrap();
        let sig_item = signer.ecdsa_item(digest, false);
        tx.inputs[0].witness = Witness::from_stack(vec![sig_item, signer.compressed_pubkey()]);
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 5);
        roundtrip(&tx, &mut resolver, true);
    }

    #[test]
    fn roundtrip_taproot_key_path() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[13_u8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _parity) = keypair.x_only_public_key();
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&xonly.serialize());
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(script),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .taproot_signature_hash(0, &[prevout], None, None, Sighash::Default)
            .unwrap();
        let message = Message::from_digest(*digest.as_byte_array());
        let signature = secp.sign_schnorr(&message, &keypair);
        tx.inputs[0].witness = Witness::from_stack(vec![signature[..].to_vec()]);
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 0);
        roundtrip(&tx, &mut resolver, true);
    }

    #[test]
    fn roundtrip_taproot_script_path_uses_uncompressed_envelope() {
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&[3_u8; 32]);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(script),
        };
        let prev_tx = funding_tx(prevout);
        let tx = spend_of(
            &prev_tx,
            Script::new(),
            Witness::from_stack(vec![vec![4_u8; 64], vec![0x51, 0x60], vec![5_u8; 33]]),
        );
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 0);
        roundtrip(&tx, &mut resolver, true);
    }

    #[test]
    fn taproot_nonempty_scriptsig_falls_back_to_uncompressed_envelope() {
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&[9_u8; 32]);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(script),
        };
        let prev_tx = funding_tx(prevout.clone());
        let kind = super::prevout_kind(prevout.script_pubkey.as_bytes());
        let canonical = spend_of(
            &prev_tx,
            Script::new(),
            Witness::from_stack(vec![vec![7_u8; 64]]),
        );
        assert!(
            super::compressed_signature(&canonical.inputs[0], &kind).is_some(),
            "empty-scriptSig key-path witness must take the compressed path"
        );
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 0);
        roundtrip(&canonical, &mut resolver, true);

        let tx = spend_of(
            &prev_tx,
            Script::from_bytes(vec![0x51]),
            Witness::from_stack(vec![vec![7_u8; 64]]),
        );
        assert!(
            super::compressed_signature(&tx.inputs[0], &kind).is_none(),
            "P2TR input with a non-empty scriptSig must fall back to the uncompressed envelope"
        );
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 0);
        roundtrip(&tx, &mut resolver, true);
    }

    #[test]
    fn roundtrip_p2sh_multisig_and_output_shapes() {
        let signer = Signer::new(15);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: {
                let mut script = vec![0xa9, 0x14];
                script.extend_from_slice(&[8_u8; 20]);
                script.push(0x87);
                Script::from_bytes(script)
            },
        };
        let prev_tx = funding_tx(prevout);
        let mut script_sig = vec![0x00];
        script_sig.extend_from_slice(&super::push_data(
            &signer.ecdsa_item(Hash256::default(), false),
        ));
        script_sig.extend_from_slice(&super::push_data(&[0x52, 0x21]));
        let tx = spend_of(&prev_tx, Script::from_bytes(script_sig), Witness::new());
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 0);
        roundtrip(&tx, &mut resolver, true);

        let mut multi = Tx {
            version: 3,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[1_u8; 32])), 0),
                    sequence: Sequence::from_consensus(0),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[2_u8; 32])), 1),
                    sequence: Sequence::from_consensus(0xffff_fffe),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[3_u8; 32])), 2),
                    sequence: Sequence::from_consensus(0xffff_ffff),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[4_u8; 32])), 3),
                    sequence: Sequence::from_consensus(0x1234_5678),
                    script_sig: Script::from_bytes(vec![0x51]),
                    witness: Witness::from_stack(vec![vec![9_u8; 3]]),
                },
            ],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: Script::from_bytes(vec![0x6a, 0x02, 0xaa, 0xbb]),
                },
                TxOut {
                    value: Amount::from_sat(2),
                    script_pubkey: Script::from_bytes({
                        let mut s = vec![0x41];
                        s.extend_from_slice(&[5_u8; 65]);
                        s.push(0xac);
                        s
                    }),
                },
                TxOut {
                    value: Amount::from_sat(3),
                    script_pubkey: Script::from_bytes({
                        let mut s = vec![0x21];
                        s.extend_from_slice(&[5_u8; 33]);
                        s.push(0xac);
                        s
                    }),
                },
                TxOut {
                    value: Amount::from_sat(4),
                    script_pubkey: p2pkh_script([6_u8; 20]),
                },
                TxOut {
                    value: Amount::from_sat(5),
                    script_pubkey: Script::from_bytes({
                        let mut s = vec![0xa9, 0x14];
                        s.extend_from_slice(&[6_u8; 20]);
                        s.push(0x87);
                        s
                    }),
                },
                TxOut {
                    value: Amount::from_sat(6),
                    script_pubkey: p2wpkh_script([6_u8; 20]),
                },
                TxOut {
                    value: Amount::from_sat(7),
                    script_pubkey: Script::from_bytes({
                        let mut s = vec![0x00, 0x20];
                        s.extend_from_slice(&[6_u8; 32]);
                        s
                    }),
                },
                TxOut {
                    value: Amount::from_sat(8),
                    script_pubkey: Script::from_bytes({
                        let mut s = vec![0x51, 0x20];
                        s.extend_from_slice(&[6_u8; 32]);
                        s
                    }),
                },
            ],
            lock_time: LockTime::from_consensus(800_000),
        };
        let mut resolver = MapResolver::default();
        let compressed = roundtrip(&multi, &mut resolver, false);
        assert!(compressed.len() < consensus_bytes(&multi).len());
        multi.lock_time = LockTime::from_consensus(1_700_000_000);
        roundtrip(&multi, &mut resolver, false);
    }

    #[test]
    fn minimum_height_sentinel_and_locktime_only_candidate_roundtrip() {
        let tx = funding_tx(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2wpkh_script([2_u8; 20]),
        });
        let mut resolver = MapResolver::default();
        let (compressed, _) = compress_transaction(
            &tx,
            &mut resolver,
            CompressOptions {
                compress_outpoints: true,
            },
        )
        .unwrap();
        assert_eq!(compressed[0] & 0x80, 0, "sentinel must encode as zero");
        let restored = decompress_transaction(&compressed, &mut resolver).unwrap();
        assert_eq!(restored, tx);

        let mut locked = tx.clone();
        locked.lock_time = LockTime::from_consensus(500_000);
        let (compressed, _) = compress_transaction(
            &locked,
            &mut resolver,
            CompressOptions {
                compress_outpoints: true,
            },
        )
        .unwrap();
        assert_eq!(compressed[0] & 0x80, 0x80, "locktime candidate must encode");
        assert_eq!(
            compressed[0] & 0x40,
            0x40,
            "locktime presence bit must be set"
        );
        let restored = decompress_transaction(&compressed, &mut resolver).unwrap();
        assert_eq!(restored, locked);
    }

    #[test]
    fn missing_context_degrades_compress_but_refuses_decompress() {
        let signer = Signer::new(17);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2wpkh_script(signer.pubkey_hash()),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .segwit_v0_signature_hash_raw(
                0,
                p2pkh_script(signer.pubkey_hash()).as_bytes(),
                prevout.value,
                1,
            )
            .unwrap();
        tx.inputs[0].witness = Witness::from_stack(vec![
            signer.ecdsa_item(digest, false),
            signer.compressed_pubkey(),
        ]);

        let mut empty = MapResolver::default();
        let (compressed, warnings) = compress_transaction(
            &tx,
            &mut empty,
            CompressOptions {
                compress_outpoints: true,
            },
        )
        .unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("UTXO(0): "), "{warnings:?}");
        let restored = decompress_transaction(&compressed, &mut empty).unwrap();
        assert_eq!(restored, tx);

        let mut full = MapResolver::default();
        full.register_tx(100, &prev_tx, 0);
        let (compressed, warnings) = compress_transaction(
            &tx,
            &mut full,
            CompressOptions {
                compress_outpoints: true,
            },
        )
        .unwrap();
        assert_eq!(warnings, Vec::<String>::new());
        let mut empty = MapResolver::default();
        let error = decompress_transaction(&compressed, &mut empty).unwrap_err();
        assert!(
            matches!(error, CodecError::BodyMissing(_)),
            "compressed outpoint without its block: {error:?}"
        );
    }

    #[test]
    fn production_resolver_resolves_through_block_bodies() {
        use std::sync::Arc;

        use bitcoin_rs_storage::block_body::BlockBodySource;
        use sonic_rs::json;

        use crate::context::Context;
        use crate::handlers::tx::{compressrawtransaction, decompressrawtransaction};

        struct StubBody(Vec<u8>);
        impl BlockBodySource for StubBody {
            fn block_body(
                &self,
                height: u32,
                _hash: bitcoin_rs_consensus::primitives::BlockHash,
            ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError>
            {
                Ok((height == 100).then(|| self.0.clone()))
            }
        }

        struct StubTxIndex(Tx, bitcoin_rs_index::TransactionBlock);
        impl bitcoin_rs_index::DerivedIndexQuery for StubTxIndex {
            fn transaction(
                &self,
                _txid: &Txid,
            ) -> Result<Option<Tx>, bitcoin_rs_index::TxQueryError> {
                Ok(None)
            }
            fn outpoint_value(
                &self,
                _outpoint: &OutPoint,
            ) -> Result<Option<u64>, bitcoin_rs_index::TxQueryError> {
                Ok(None)
            }
            fn transaction_block(
                &self,
                txid: &Txid,
            ) -> Result<
                Option<(Tx, bitcoin_rs_index::TransactionBlock)>,
                bitcoin_rs_index::TxQueryError,
            > {
                Ok((self.0.txid() == *txid).then(|| (self.0.clone(), self.1)))
            }
            fn index_info(
                &self,
            ) -> Result<bitcoin_rs_index::DerivedIndexInfo, bitcoin_rs_index::TxQueryError>
            {
                Ok(bitcoin_rs_index::DerivedIndexInfo {
                    synced: true,
                    best_block_height: 100,
                    applied_height: 100,
                    historical_height: 100,
                    verified_height: 100,
                    coverage_height: 100,
                })
            }
        }

        let signer = Signer::new(19);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2wpkh_script(signer.pubkey_hash()),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .segwit_v0_signature_hash_raw(
                0,
                p2pkh_script(signer.pubkey_hash()).as_bytes(),
                prevout.value,
                1,
            )
            .unwrap();
        tx.inputs[0].witness = Witness::from_stack(vec![
            signer.ecdsa_item(digest, false),
            signer.compressed_pubkey(),
        ]);

        let mut block = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
        block.txs = vec![prev_tx.clone()];
        let body = consensus_bytes(&block);

        let mut ctx = Context::new();
        ctx.compressed_transactions = true;
        ctx.chain.block_body_source = Some(Arc::new(StubBody(body)));
        ctx.indexes.derived_index = Some(Arc::new(StubTxIndex(
            prev_tx.clone(),
            bitcoin_rs_index::TransactionBlock {
                height: 100,
                hash: block.block_hash().into(),
            },
        )));
        ctx.chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord {
                hash: block.block_hash(),
                height: 100,
                body_size: 0,
                header: None,
                tx_count: 1,
                time: 0,
            });
        let ctx = Arc::new(ctx);
        let raw_hex = bitcoin::hex::DisplayHex::to_lower_hex_string(&consensus_bytes(&tx));
        let latch = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        let compressed = compressrawtransaction(&ctx, &json!([raw_hex]), &latch).unwrap();
        assert!(
            compressed
                .get("warnings")
                .and_then(Value::as_array)
                .is_some_and(sonic_rs::Array::is_empty),
            "body-backed resolver must leave no warning: {compressed}"
        );
        let compressed_hex = compressed
            .get("result")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        let restored = decompressrawtransaction(&ctx, &json!([compressed_hex]), &latch).unwrap();
        assert_eq!(restored.as_str().unwrap(), raw_hex);
    }

    #[test]
    fn malformed_streams_are_rejected() {
        let vector = &fixture_vectors()[0];
        let compressed = hex_bytes(
            vector
                .get("compressed_hex")
                .and_then(Value::as_str)
                .unwrap(),
        );
        let mut resolver = fixture_resolver(vector);

        let error =
            decompress_transaction(&compressed[..compressed.len() - 3], &mut resolver).unwrap_err();
        assert_eq!(error, CodecError::Truncated);
        let mut trailed = compressed.clone();
        trailed.push(0);
        let error = decompress_transaction(&trailed, &mut resolver).unwrap_err();
        assert_eq!(error, CodecError::NonCanonical);
        let mut padded = compressed.clone();
        padded[5] |= 0x01;
        let error = decompress_transaction(&padded, &mut resolver).unwrap_err();
        assert_eq!(error, CodecError::NonCanonical);
        let wpkh = &fixture_vectors()[1];
        let wpkh_compressed =
            hex_bytes(wpkh.get("compressed_hex").and_then(Value::as_str).unwrap());
        let mut wpkh_resolver = fixture_resolver(wpkh);
        let mut forged = wpkh_compressed;
        forged[20] ^= 0xff;
        let error = decompress_transaction(&forged, &mut wpkh_resolver).unwrap_err();
        assert_eq!(error, CodecError::SignatureUnrecoverable);
        let error = decompress_transaction(&[], &mut resolver).unwrap_err();
        assert_eq!(error, CodecError::Truncated);
        resolver.cancelled = true;
        let error = decompress_transaction(&compressed, &mut resolver).unwrap_err();
        assert_eq!(error, CodecError::Cancelled);
    }

    #[cfg(test)]
    struct BodyResolver {
        heights: HashMap<Txid, (u32, u32, u32, u32)>,
        txouts: HashMap<OutPoint, (TxOut, u32)>,
        at: HashMap<(u32, u32), OutPoint>,
    }

    #[cfg(test)]
    impl BodyResolver {
        fn from_bodies(dir: &std::path::Path) -> Self {
            let mut resolver = Self {
                heights: HashMap::new(),
                txouts: HashMap::new(),
                at: HashMap::new(),
            };
            let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "bin"))
                .collect();
            entries.sort();
            for path in entries {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let (height, hash) = name.split_once('-').unwrap();
                let height: u32 = height.parse().unwrap();
                let bytes = std::fs::read(&path).unwrap();
                let digest = {
                    use sha2::{Digest as _, Sha256};
                    let first = Sha256::digest(&bytes[..80]);
                    Sha256::digest(first)
                };
                let mut displayed = digest.to_vec();
                displayed.reverse();
                assert_eq!(
                    bitcoin::hex::DisplayHex::to_lower_hex_string(&displayed),
                    hash.trim_end_matches(".bin"),
                    "body file hash mismatch: {name}"
                );
                let block = ParsedBlock::parse_exact(&bytes).unwrap();
                let mut flat = 0_u32;
                for (tx_index, parsed) in block.transactions().iter().enumerate() {
                    let tx = parsed.materialize();
                    resolver.heights.insert(
                        tx.txid(),
                        (
                            height,
                            u32::try_from(tx_index).unwrap(),
                            flat,
                            u32::try_from(tx.outputs.len()).unwrap(),
                        ),
                    );
                    for (vout, output) in tx.outputs.iter().enumerate() {
                        let vout = u32::try_from(vout).unwrap();
                        let outpoint = OutPoint::new(tx.txid(), vout);
                        resolver.txouts.insert(outpoint, (output.clone(), height));
                        resolver.at.insert((height, flat + vout), outpoint);
                    }
                    flat += u32::try_from(tx.outputs.len()).unwrap();
                }
            }
            resolver
        }
    }

    #[cfg(test)]
    impl PrevoutResolver for BodyResolver {
        fn prevout(&mut self, outpoint: &OutPoint) -> Result<Option<ResolvedPrevout>, LookupError> {
            Ok(self
                .txouts
                .get(outpoint)
                .map(|(txout, height)| ResolvedPrevout {
                    txout: txout.clone(),
                    confirmed_height: Some(*height),
                }))
        }

        fn flat_output_index(
            &mut self,
            height: u32,
            txid: &Txid,
            vout: u32,
        ) -> Result<Option<u32>, LookupError> {
            Ok(match self.heights.get(txid) {
                Some((h, _index, first, count)) if *h == height && vout < *count => {
                    Some(first + vout)
                }
                _ => None,
            })
        }

        fn outpoint_at(
            &mut self,
            height: u32,
            flat_index: u32,
        ) -> Result<Option<(OutPoint, ResolvedPrevout)>, LookupError> {
            Ok(self.at.get(&(height, flat_index)).map(|outpoint| {
                let (txout, _) = self.txouts.get(outpoint).unwrap();
                (
                    *outpoint,
                    ResolvedPrevout {
                        txout: txout.clone(),
                        confirmed_height: Some(height),
                    },
                )
            }))
        }

        fn cancelled(&self) -> bool {
            false
        }
    }

    #[test]
    #[ignore = "requires BITCOIN_RS_BIP337_MAINNET_BODIES with mainnet block bodies"]
    fn mainnet_bodies_truth() {
        let Ok(dir) = std::env::var("BITCOIN_RS_BIP337_MAINNET_BODIES") else {
            panic!(
                "BLOCKED: BITCOIN_RS_BIP337_MAINNET_BODIES is unset; download mainnet bodies \
             833265..833280 to run the BIP337 fixture truth loop"
            );
        };
        let resolver = BodyResolver::from_bodies(std::path::Path::new(&dir));
        for vector in fixture_vectors() {
            let name = vector
                .get("name")
                .and_then(Value::as_str)
                .unwrap()
                .to_owned();
            let raw: Tx = deserialize(&hex_bytes(
                vector.get("raw_hex").and_then(Value::as_str).unwrap(),
            ))
            .unwrap();
            assert_eq!(
                raw.txid().to_string(),
                vector.get("txid").and_then(Value::as_str).unwrap()
            );
            assert_eq!(
                raw.wtxid().to_string(),
                vector.get("wtxid").and_then(Value::as_str).unwrap()
            );
            for input in vector.get("inputs").and_then(Value::as_array).unwrap() {
                let prevout_txid =
                    Txid::from_str(input.get("prevout_txid").and_then(Value::as_str).unwrap())
                        .unwrap();
                let (height, tx_index, first_flat, _count) =
                    resolver.heights.get(&prevout_txid).unwrap();
                assert_eq!(
                    *tx_index,
                    u32::try_from(
                        input
                            .get("tx_index_in_block")
                            .and_then(Value::as_u64)
                            .unwrap()
                    )
                    .unwrap(),
                    "{name} tx index in block"
                );
                let vout =
                    u32::try_from(input.get("vout").and_then(Value::as_u64).unwrap()).unwrap();
                let (txout, txout_height) = resolver
                    .txouts
                    .get(&OutPoint::new(prevout_txid, vout))
                    .unwrap();
                assert_eq!(
                    *height,
                    u32::try_from(input.get("height").and_then(Value::as_u64).unwrap()).unwrap(),
                    "{name} height"
                );
                assert_eq!(*txout_height, *height, "{name} txout height");
                assert_eq!(
                    *first_flat,
                    u32::try_from(
                        input
                            .get("cumulative_outputs_before")
                            .and_then(Value::as_u64)
                            .unwrap()
                    )
                    .unwrap(),
                    "{name} cumulative outputs before"
                );
                assert_eq!(
                    first_flat + vout,
                    u32::try_from(
                        input
                            .get("flat_output_index")
                            .and_then(Value::as_u64)
                            .unwrap()
                    )
                    .unwrap(),
                    "{name} flat index"
                );
                assert_eq!(
                    txout.script_pubkey.as_bytes(),
                    hex_bytes(
                        input
                            .get("prevout_script_hex")
                            .and_then(Value::as_str)
                            .unwrap()
                    )
                    .as_slice(),
                    "{name} prevout script"
                );
                assert_eq!(
                    txout.value.to_sat(),
                    input.get("value_sats").and_then(Value::as_u64).unwrap(),
                    "{name} value"
                );
            }
            let mut compress_resolver = BodyResolver::from_bodies(std::path::Path::new(&dir));
            let start = std::time::Instant::now();
            let mut compressed = Vec::new();
            for _ in 0..200 {
                let (bytes, warnings) = compress_transaction(
                    &raw,
                    &mut compress_resolver,
                    CompressOptions {
                        compress_outpoints: true,
                    },
                )
                .unwrap();
                assert!(warnings.is_empty(), "{name}: {warnings:?}");
                compressed = bytes;
            }
            let encode_elapsed = start.elapsed();
            assert_eq!(
                compressed,
                hex_bytes(
                    vector
                        .get("compressed_hex")
                        .and_then(Value::as_str)
                        .unwrap()
                ),
                "{name} compressed bytes"
            );
            let start = std::time::Instant::now();
            let mut restored = raw.clone();
            for _ in 0..200 {
                restored = decompress_transaction(&compressed, &mut compress_resolver).unwrap();
            }
            let decode_elapsed = start.elapsed();
            assert_eq!(restored, raw, "{name} restored");
            eprintln!(
                "bip337 {name}: raw={} compressed={} ratio_permille={} encode_us_per={:.1} decode_us_per={:.1}",
                consensus_bytes(&raw).len(),
                compressed.len(),
                compressed.len() * 1000 / consensus_bytes(&raw).len(),
                encode_elapsed.as_secs_f64() * 1e6 / 200.0,
                decode_elapsed.as_secs_f64() * 1e6 / 200.0,
            );
        }
    }

    fn compact_of(der_plus_hashtype: &[u8]) -> [u8; 64] {
        let parsed = bitcoin::secp256k1::ecdsa::Signature::from_der(
            &der_plus_hashtype[..der_plus_hashtype.len() - 1],
        )
        .unwrap();
        parsed.serialize_compact()
    }

    #[test]
    fn shared_sighash_cache_recovers_every_input() {
        let signer_a = Signer::new(31);
        let signer_b = Signer::new(32);
        let prevout_a = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2pkh_script(signer_a.pubkey_hash()),
        };
        let prevout_b = TxOut {
            value: Amount::from_sat(60_000),
            script_pubkey: p2wpkh_script(signer_b.pubkey_hash()),
        };
        let prev_tx_a = funding_tx(prevout_a.clone());
        let prev_tx_b = funding_tx(prevout_b.clone());

        let mut tx = Tx {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(prev_tx_a.txid(), 0),
                    script_sig: Script::new(),
                    sequence: Sequence::from_consensus(0xffff_fffd),
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint::new(prev_tx_b.txid(), 0),
                    script_sig: Script::new(),
                    sequence: Sequence::from_consensus(0xffff_fffd),
                    witness: Witness::new(),
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: Script::from_bytes(
                    vec![0x00, 0x14].into_iter().chain([7_u8; 20]).collect(),
                ),
            }],
            lock_time: LockTime::ZERO,
        };
        let digest_a = SighashCache::new(&tx)
            .legacy_signature_hash(0, prevout_a.script_pubkey.as_bytes(), 1)
            .unwrap();
        let digest_b = SighashCache::new(&tx)
            .segwit_v0_signature_hash_raw(
                1,
                p2pkh_script(signer_b.pubkey_hash()).as_bytes(),
                prevout_b.value,
                1,
            )
            .unwrap();
        let sig_item_a = signer_a.ecdsa_item(digest_a, false);
        let mut script_sig = super::push_data(&sig_item_a);
        script_sig.extend_from_slice(&super::push_data(&signer_a.compressed_pubkey()));
        tx.inputs[0].script_sig = Script::from_bytes(script_sig);
        let sig_item_b = signer_b.ecdsa_item(digest_b, false);
        tx.inputs[1].witness = Witness::from_stack(vec![sig_item_b, signer_b.compressed_pubkey()]);

        let cache = SighashCache::new(&tx);
        let compact_a = compact_of(&sig_item_a);
        let compact_b = compact_of(&tx.inputs[1].witness[0]);
        let kind_a = super::prevout_kind(prevout_a.script_pubkey.as_bytes());
        let kind_b = super::prevout_kind(prevout_b.script_pubkey.as_bytes());
        let resolved_a = ResolvedPrevout {
            txout: prevout_a,
            confirmed_height: Some(100),
        };
        let resolved_b = ResolvedPrevout {
            txout: prevout_b,
            confirmed_height: Some(101),
        };
        let recovered_a = super::recover_pubkey(
            &cache,
            &super::Recovery {
                index: 0,
                sig: &compact_a,
                hash_type: 1,
                kind: &kind_a,
                prevout: &resolved_a,
                stored_pkh: None,
            },
        )
        .unwrap();
        assert_eq!(recovered_a, signer_a.compressed_pubkey());
        let recovered_b = super::recover_pubkey(
            &cache,
            &super::Recovery {
                index: 1,
                sig: &compact_b,
                hash_type: 1,
                kind: &kind_b,
                prevout: &resolved_b,
                stored_pkh: None,
            },
        )
        .unwrap();
        assert_eq!(recovered_b, signer_b.compressed_pubkey());

        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx_a, 0);
        resolver.register_tx(101, &prev_tx_b, 0);
        let (compressed, warnings) = compress_transaction(
            &tx,
            &mut resolver,
            CompressOptions {
                compress_outpoints: true,
            },
        )
        .unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let plan = super::decompress_prepare(&compressed, &mut resolver).unwrap();
        assert_eq!(plan.inputs.len(), 2);
        let restored = super::decompress_finalize(plan, &resolver).unwrap();
        assert_eq!(&restored, &tx);
        assert_eq!(
            &super::decompress_transaction(&compressed, &mut resolver).unwrap(),
            &tx
        );
    }

    #[test]
    fn production_resolver_clones_only_the_requested_output() {
        use std::sync::Arc;

        use bitcoin_rs_storage::block_body::BlockBodySource;

        use crate::context::Context;

        struct StubBody(Vec<u8>);
        impl BlockBodySource for StubBody {
            fn block_body(
                &self,
                height: u32,
                _hash: bitcoin_rs_consensus::primitives::BlockHash,
            ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError>
            {
                Ok((height == 100).then(|| self.0.clone()))
            }
        }

        struct StubTxIndex(Tx, bitcoin_rs_index::TransactionBlock);
        impl bitcoin_rs_index::DerivedIndexQuery for StubTxIndex {
            fn transaction(
                &self,
                _txid: &Txid,
            ) -> Result<Option<Tx>, bitcoin_rs_index::TxQueryError> {
                Ok(None)
            }
            fn outpoint_value(
                &self,
                _outpoint: &OutPoint,
            ) -> Result<Option<u64>, bitcoin_rs_index::TxQueryError> {
                Ok(None)
            }
            fn transaction_block(
                &self,
                txid: &Txid,
            ) -> Result<
                Option<(Tx, bitcoin_rs_index::TransactionBlock)>,
                bitcoin_rs_index::TxQueryError,
            > {
                Ok((self.0.txid() == *txid).then(|| (self.0.clone(), self.1)))
            }
            fn index_info(
                &self,
            ) -> Result<bitcoin_rs_index::DerivedIndexInfo, bitcoin_rs_index::TxQueryError>
            {
                Ok(bitcoin_rs_index::DerivedIndexInfo {
                    synced: true,
                    best_block_height: 100,
                    applied_height: 100,
                    historical_height: 100,
                    verified_height: 100,
                    coverage_height: 100,
                })
            }
        }

        let funding = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x01, 0x2a]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(11_000),
                    script_pubkey: p2pkh_script([1_u8; 20]),
                },
                TxOut {
                    value: Amount::from_sat(22_000),
                    script_pubkey: p2wpkh_script([2_u8; 20]),
                },
                TxOut {
                    value: Amount::from_sat(33_000),
                    script_pubkey: p2pkh_script([3_u8; 20]),
                },
            ],
            lock_time: LockTime::ZERO,
        };
        let txid = funding.txid();

        let mut block = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
        block.txs = vec![funding.clone()];
        let body = consensus_bytes(&block);

        let mut ctx = Context::new();
        ctx.chain.block_body_source = Some(Arc::new(StubBody(body)));
        ctx.indexes.derived_index = Some(Arc::new(StubTxIndex(
            funding.clone(),
            bitcoin_rs_index::TransactionBlock {
                height: 100,
                hash: block.block_hash().into(),
            },
        )));
        ctx.chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord {
                hash: block.block_hash(),
                height: 100,
                body_size: 0,
                header: None,
                tx_count: 1,
                time: 0,
            });
        let ctx = Arc::new(ctx);
        let latch = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        let mut resolver = crate::context::RpcPrevoutResolver::new(&ctx, latch).unwrap();

        for (vout, expected) in funding.outputs.iter().enumerate() {
            let vout = u32::try_from(vout).unwrap();
            let resolved = resolver
                .prevout(&OutPoint::new(txid, vout))
                .unwrap()
                .expect("funding output must resolve");
            assert_eq!(&resolved.txout, expected, "vout {vout} must match");
            assert_eq!(resolved.confirmed_height, Some(100));
        }
        let middle = resolver.prevout(&OutPoint::new(txid, 1)).unwrap().unwrap();
        assert_eq!(middle.txout, funding.outputs[1]);
        assert_ne!(middle.txout, funding.outputs[0]);
        assert_ne!(middle.txout, funding.outputs[2]);

        assert_eq!(resolver.flat_output_index(100, &txid, 1).unwrap(), Some(1));
        for flat in [0_u32, 1, 2] {
            let (outpoint, resolved) = resolver
                .outpoint_at(100, flat)
                .unwrap()
                .expect("flat index must locate an output");
            let vout = flat;
            assert_eq!(outpoint, OutPoint::new(txid, vout));
            assert_eq!(
                resolved.txout,
                funding.outputs[usize::try_from(vout).unwrap()]
            );
            assert_eq!(resolved.confirmed_height, Some(100));
        }

        assert!(resolver.prevout(&OutPoint::new(txid, 9)).unwrap().is_none());
        assert!(resolver.outpoint_at(100, 9).unwrap().is_none());
    }

    struct CountingBodies {
        bodies: HashMap<u32, Vec<u8>>,
        loads: std::sync::Mutex<HashMap<u32, usize>>,
    }

    impl bitcoin_rs_storage::block_body::BlockBodySource for CountingBodies {
        fn block_body(
            &self,
            height: u32,
            _hash: bitcoin_rs_consensus::primitives::BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
            if let Some(body) = self.bodies.get(&height) {
                *self.loads.lock().unwrap().entry(height).or_default() += 1;
                Ok(Some(body.clone()))
            } else {
                Ok(None)
            }
        }
    }

    fn cycling_fixture(
        heights: &[u32],
    ) -> (
        crate::context::Context,
        std::sync::Arc<CountingBodies>,
        Vec<Txid>,
    ) {
        use std::sync::Arc;

        let mut ctx = crate::context::Context::new();
        let mut bodies = HashMap::new();
        let mut txids = Vec::new();
        let mut changes = bitcoin_rs_storage::utxo::contract::BlockChanges::default();
        for (slot, &height) in heights.iter().enumerate() {
            let funding = funding_tx(TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(vec![0x6a, u8::try_from(slot).unwrap()]),
            });
            let txid = funding.txid();
            let mut block = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
            block.txs = vec![funding.clone()];
            bodies.insert(height, consensus_bytes(&block));
            changes.add(bitcoin_rs_storage::utxo::contract::UtxoAdd::new(
                OutPoint::new(txid, 0),
                funding.outputs[0].clone(),
                false,
                height,
            ));
            ctx.chain
                .add_block(bitcoin_rs_index::block_log::BlockRecord {
                    hash: bitcoin_rs_consensus::primitives::BlockHash::from(
                        bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                            &[u8::try_from(height).unwrap(); 32],
                        ),
                    ),
                    height,
                    body_size: 0,
                    header: None,
                    tx_count: 1,
                    time: 0,
                });
            txids.push(txid);
        }
        ctx.populate_fixture_coins(&changes).unwrap();
        let source = Arc::new(CountingBodies {
            bodies,
            loads: std::sync::Mutex::new(HashMap::new()),
        });
        let object: Arc<dyn bitcoin_rs_storage::block_body::BlockBodySource> = source.clone();
        ctx.chain.block_body_source = Some(object);
        (ctx, source, txids)
    }

    fn cycling_spend(txids: &[Txid], inputs: usize) -> Tx {
        Tx {
            version: 2,
            inputs: txids
                .iter()
                .cycle()
                .take(inputs)
                .map(|txid| TxIn {
                    previous_output: OutPoint::new(*txid, 0),
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: p2wpkh_script([7_u8; 20]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn assert_loads(source: &CountingBodies, heights: &[u32], per_height: usize) {
        let loads = source.loads.lock().unwrap();
        assert_eq!(loads.len(), heights.len(), "{loads:?}");
        let mut total = 0_usize;
        for height in heights {
            let count = loads.get(height).copied().unwrap_or(0);
            assert_eq!(count, per_height, "height {height}");
            total += count;
        }
        assert_eq!(total, heights.len() * per_height);
    }

    #[test]
    fn five_heights_cycling_loads_each_body_once() {
        use std::sync::Arc;

        let heights: Vec<u32> = (100..105).collect();
        let (ctx, source, txids) = cycling_fixture(&heights);
        let ctx = Arc::new(ctx);
        let spend = cycling_spend(&txids, 10);

        let latch = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        let mut resolver = crate::context::RpcPrevoutResolver::new(&ctx, latch).unwrap();
        let (compressed, warnings) = compress_transaction(
            &spend,
            &mut resolver,
            CompressOptions {
                compress_outpoints: true,
            },
        )
        .unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_loads(&source, &heights, 1);

        let latch = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        let mut resolver = crate::context::RpcPrevoutResolver::new(&ctx, latch).unwrap();
        let plan = super::decompress_prepare(&compressed, &mut resolver).unwrap();
        let restored = super::decompress_finalize(plan, &resolver).unwrap();
        assert_eq!(&restored, &spend);
        assert_loads(&source, &heights, 2);
    }

    #[test]
    fn cumulative_body_budget_fails_closed_past_grouped_heights() {
        use std::sync::Arc;

        let heights: Vec<u32> = (100..110).collect();
        let (ctx, source, txids) = cycling_fixture(&heights);
        let ctx = Arc::new(ctx);
        let spend = cycling_spend(&txids, 10);

        let latch = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        let mut resolver = crate::context::RpcPrevoutResolver::new(&ctx, latch).unwrap();
        let error = compress_transaction(
            &spend,
            &mut resolver,
            CompressOptions {
                compress_outpoints: true,
            },
        )
        .unwrap_err();
        assert_eq!(error, CodecError::LimitExceeded(super::Limit::Loads));
        let loads = source.loads.lock().unwrap();
        let total: usize = loads.values().sum();
        assert_eq!(total, super::MAX_CUMULATIVE_BODY_LOADS);
    }
}
