use std::sync::{LazyLock, OnceLock};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::primitives::{
    Amount, Hash256, LockTime, OutPoint, Sequence, Tx, TxOut,
    block::TransactionView,
    encode::{
        ConsensusEncode, Sha256Sink, Sink as _, compact_len, consensus_bytes,
        finalize_double_sha256, write_compact, write_script,
    },
    varint,
};

#[derive(Clone, Copy, Debug)]
pub enum TxView<'t> {
    Owned(&'t Tx),
    View(TransactionView<'t>),
}

impl<'t> From<&'t Tx> for TxView<'t> {
    fn from(tx: &'t Tx) -> Self {
        Self::Owned(tx)
    }
}

impl<'t> From<TransactionView<'t>> for TxView<'t> {
    fn from(view: TransactionView<'t>) -> Self {
        Self::View(view)
    }
}

impl<'t> TxView<'t> {
    #[must_use]
    pub fn version(&self) -> u32 {
        match self {
            Self::Owned(tx) => tx.version,
            Self::View(v) => v.version(),
        }
    }

    #[must_use]
    pub fn lock_time(&self) -> LockTime {
        match self {
            Self::Owned(tx) => tx.lock_time,
            Self::View(v) => v.lock_time(),
        }
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        match self {
            Self::Owned(tx) => tx.inputs.len(),
            Self::View(v) => v.input_count(),
        }
    }

    #[must_use]
    pub fn output_count(&self) -> usize {
        match self {
            Self::Owned(tx) => tx.outputs.len(),
            Self::View(v) => v.output_count(),
        }
    }

    #[must_use]
    pub fn input_outpoint(&self, i: usize) -> OutPoint {
        match self {
            Self::Owned(tx) => tx.inputs[i].previous_output,
            Self::View(v) => v.input_outpoint(i),
        }
    }

    #[must_use]
    pub fn input_sequence(&self, i: usize) -> Sequence {
        match self {
            Self::Owned(tx) => tx.inputs[i].sequence,
            Self::View(v) => v.input_sequence(i),
        }
    }

    #[must_use]
    pub fn input_script_sig(&self, i: usize) -> &'t [u8] {
        match self {
            Self::Owned(tx) => &tx.inputs[i].script_sig,
            Self::View(v) => v.input_script_sig(i),
        }
    }

    #[must_use]
    pub fn output_value(&self, i: usize) -> Amount {
        match self {
            Self::Owned(tx) => tx.outputs[i].value,
            Self::View(v) => v.output_value(i),
        }
    }

    #[must_use]
    pub fn output_script(&self, i: usize) -> &'t [u8] {
        match self {
            Self::Owned(tx) => &tx.outputs[i].script_pubkey,
            Self::View(v) => v.output_script(i),
        }
    }

    pub fn encode_output<W: crate::primitives::encode::Sink>(&self, i: usize, writer: &mut W) {
        match self {
            Self::Owned(tx) => tx.outputs[i].consensus_encode(writer),
            Self::View(v) => {
                writer.write_all(&v.output_value(i).to_le_bytes());
                write_script(writer, v.output_script(i));
            }
        }
    }

    #[must_use]
    pub fn output_consensus_bytes(&self, i: usize) -> Vec<u8> {
        match self {
            Self::Owned(tx) => consensus_bytes(&tx.outputs[i]),
            Self::View(v) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&v.output_value(i).to_le_bytes());
                let script = v.output_script(i);
                bytes.extend_from_slice(varint::encode(compact_len(script.len())).as_slice());
                bytes.extend_from_slice(script);
                bytes
            }
        }
    }

    #[must_use]
    pub fn is_coinbase(&self) -> bool {
        match self {
            Self::Owned(tx) => tx.is_coinbase(),
            Self::View(v) => v.is_coinbase(),
        }
    }

    #[must_use]
    pub fn witness_item_count(&self, input: usize) -> usize {
        match self {
            Self::Owned(tx) => tx.inputs[input].witness.len(),
            Self::View(v) => v.witness_item_count(input),
        }
    }

    #[must_use]
    pub fn witness_item(&self, input: usize, item: usize) -> &'t [u8] {
        match self {
            Self::Owned(tx) => &tx.inputs[input].witness[item],
            Self::View(v) => v.witness_item(input, item),
        }
    }
}

pub const CODESEPARATOR_POSITION: u32 = 0xFFFF_FFFF;

/// BIP342 leaf version byte for tapscript leaves.
#[cfg(test)]
const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Sighash {
    All,
    None,
    Single,
    AllAnyoneCanPay,
    NoneAnyoneCanPay,
    SingleAnyoneCanPay,
    Default,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SighashError {
    #[error("input index {index} out of range for {total} inputs")]
    InputOutOfRange { index: usize, total: usize },
    #[error("SIGHASH_DEFAULT is valid only for taproot")]
    DefaultOnlyTaproot,
    #[error("invalid taproot annex: {0}")]
    InvalidAnnex(#[source] AnnexError),
    #[error(
        "sighash single requires output at input index {input_index}; outputs length {outputs_length}"
    )]
    SingleMissingOutput {
        input_index: usize,
        outputs_length: usize,
    },
    #[error("taproot prevouts length {provided} does not match input count {expected}")]
    PrevoutsLength { provided: usize, expected: usize },
    #[error("taproot prevout at index {index} unavailable")]
    PrevoutsIndex { index: usize },
    #[error("unknown sighash type byte {0:#04x}")]
    UnknownType(u8),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnnexError {
    #[error("annex is empty")]
    Empty,
    #[error("annex must start with the 0x50 prefix byte")]
    InvalidFirstByte,
}

#[derive(Copy, Clone)]
enum EcdsaType {
    All,
    None,
    Single,
    AllAnyoneCanPay,
    NoneAnyoneCanPay,
    SingleAnyoneCanPay,
}

impl EcdsaType {
    const fn from_consensus(n: u32) -> Self {
        let masked = (n & 0x1f) | (n & 0x80);
        match masked {
            0x01 => Self::All,
            0x02 => Self::None,
            0x03 => Self::Single,
            0x81 => Self::AllAnyoneCanPay,
            0x82 => Self::NoneAnyoneCanPay,
            0x83 => Self::SingleAnyoneCanPay,
            _ if n & 0x80 == 0x80 => Self::AllAnyoneCanPay,
            _ => Self::All,
        }
    }

    const fn is_anyone_can_pay(self) -> bool {
        matches!(
            self,
            Self::AllAnyoneCanPay | Self::NoneAnyoneCanPay | Self::SingleAnyoneCanPay
        )
    }

    const fn is_single(self) -> bool {
        matches!(self, Self::Single | Self::SingleAnyoneCanPay)
    }

    const fn is_none(self) -> bool {
        matches!(self, Self::None | Self::NoneAnyoneCanPay)
    }

    const fn to_u32(self) -> u32 {
        match self {
            Self::All => 0x01,
            Self::None => 0x02,
            Self::Single => 0x03,
            Self::AllAnyoneCanPay => 0x81,
            Self::NoneAnyoneCanPay => 0x82,
            Self::SingleAnyoneCanPay => 0x83,
        }
    }
}

pub struct SighashCache<'t> {
    tx: TxView<'t>,
    segwit_prevouts: OnceLock<Hash256>,
    segwit_sequences: OnceLock<Hash256>,
    segwit_outputs: OnceLock<Hash256>,
    prevouts: OnceLock<Hash256>,
    taproot_amounts: OnceLock<Hash256>,
    taproot_scriptpubkeys: OnceLock<Hash256>,
    sequences: OnceLock<Hash256>,
    outputs: OnceLock<Hash256>,
}

impl<'t> SighashCache<'t> {
    #[must_use]
    pub fn new(tx: impl Into<TxView<'t>>) -> Self {
        Self {
            tx: tx.into(),
            segwit_prevouts: OnceLock::new(),
            segwit_sequences: OnceLock::new(),
            segwit_outputs: OnceLock::new(),
            prevouts: OnceLock::new(),
            taproot_amounts: OnceLock::new(),
            taproot_scriptpubkeys: OnceLock::new(),
            sequences: OnceLock::new(),
            outputs: OnceLock::new(),
        }
    }

    pub fn legacy_signature_hash(
        &self,
        input_index: usize,
        script_code: &[u8],
        sighash_type: u32,
    ) -> Result<Hash256, SighashError> {
        let total = self.tx.input_count();
        if input_index >= total {
            return Err(SighashError::InputOutOfRange {
                index: input_index,
                total,
            });
        }
        let ty = EcdsaType::from_consensus(sighash_type);
        if ty.is_single() && input_index >= self.tx.output_count() {
            return Ok(uint256_one());
        }

        let mut engine = Sha256::new();
        let writer = &mut Sha256Sink(&mut engine);
        writer.write_all(&self.tx.version().to_le_bytes());
        if ty.is_anyone_can_pay() {
            write_compact(writer, 1);
            let outpoint = self.tx.input_outpoint(input_index);
            outpoint.consensus_encode(writer);
            write_script(writer, script_code);
            writer.write_all(&self.tx.input_sequence(input_index).to_le_bytes());
        } else {
            write_compact(writer, compact_len(total));
            for n in 0..total {
                let sequence = if n != input_index && (ty.is_single() || ty.is_none()) {
                    crate::primitives::Sequence::ZERO
                } else {
                    self.tx.input_sequence(n)
                };
                let script: &[u8] = if n == input_index { script_code } else { &[] };
                let outpoint = self.tx.input_outpoint(n);
                outpoint.consensus_encode(writer);
                write_script(writer, script);
                writer.write_all(&sequence.to_le_bytes());
            }
        }
        match ty {
            EcdsaType::All | EcdsaType::AllAnyoneCanPay => {
                write_compact(writer, compact_len(self.tx.output_count()));
                for n in 0..self.tx.output_count() {
                    self.tx.encode_output(n, writer);
                }
            }
            EcdsaType::Single | EcdsaType::SingleAnyoneCanPay => {
                write_compact(writer, compact_len(input_index + 1));
                for _ in 0..input_index {
                    writer.write_all(&u64::MAX.to_le_bytes());
                    write_compact(writer, 0);
                }
                self.tx.encode_output(input_index, writer);
            }
            _ => write_compact(writer, 0),
        }
        writer.write_all(&self.tx.lock_time().to_consensus().to_le_bytes());
        writer.write_all(&sighash_type.to_le_bytes());

        Ok(finalize_double_sha256(engine))
    }

    pub fn segwit_v0_signature_hash(
        &self,
        input_index: usize,
        script_code: &[u8],
        value: crate::primitives::Amount,
        sighash_type: Sighash,
    ) -> Result<Hash256, SighashError> {
        let raw = sighash_type.to_ecdsa()?.to_u32();
        self.segwit_v0_signature_hash_raw(input_index, script_code, value, raw)
    }

    pub fn segwit_v0_signature_hash_raw(
        &self,
        input_index: usize,
        script_code: &[u8],
        value: crate::primitives::Amount,
        sighash_type: u32,
    ) -> Result<Hash256, SighashError> {
        let ty = EcdsaType::from_consensus(sighash_type);
        let total = self.tx.input_count();
        if input_index >= total {
            return Err(SighashError::InputOutOfRange {
                index: input_index,
                total,
            });
        }

        let zero = Hash256::default();
        let prevouts_hash = if ty.is_anyone_can_pay() {
            zero
        } else {
            *self.segwit_prevouts.get_or_init(|| {
                sha256_over(|writer| writer.write_all(self.prevouts().as_byte_array()))
            })
        };
        let sequences_hash = if ty.is_anyone_can_pay() || ty.is_single() || ty.is_none() {
            zero
        } else {
            *self.segwit_sequences.get_or_init(|| {
                sha256_over(|writer| writer.write_all(self.sequences().as_byte_array()))
            })
        };

        let outputs_hash = if !ty.is_single() && !ty.is_none() {
            *self.segwit_outputs.get_or_init(|| {
                sha256_over(|writer| writer.write_all(self.outputs().as_byte_array()))
            })
        } else if ty.is_single() {
            if input_index < self.tx.output_count() {
                let mut single = Sha256::new();
                let single_writer = &mut Sha256Sink(&mut single);
                self.tx.encode_output(input_index, single_writer);
                finalize_double_sha256(single)
            } else {
                zero
            }
        } else {
            zero
        };

        let mut engine = Sha256::new();
        let writer = &mut Sha256Sink(&mut engine);
        writer.write_all(&self.tx.version().to_le_bytes());
        writer.write_all(prevouts_hash.as_byte_array());
        writer.write_all(sequences_hash.as_byte_array());
        self.tx.input_outpoint(input_index).consensus_encode(writer);
        write_script(writer, script_code);
        writer.write_all(&value.to_le_bytes());
        writer.write_all(&self.tx.input_sequence(input_index).to_le_bytes());
        writer.write_all(outputs_hash.as_byte_array());
        writer.write_all(&self.tx.lock_time().to_consensus().to_le_bytes());
        writer.write_all(&sighash_type.to_le_bytes());

        Ok(finalize_double_sha256(engine))
    }

    /// Computes the BIP341 taproot signature hash.
    ///
    /// `leaf_hash_code_separator` is `None` for key-path spends and `Some((leaf_hash,
    /// code_separator_position))` for script path spends (BIP342). The tagged hash
    /// includes Core's zero epoch byte.
    pub fn taproot_signature_hash(
        &self,
        input_index: usize,
        prevouts: &[TxOut],
        annex: Option<&[u8]>,
        leaf_hash_code_separator: Option<(Hash256, u32)>,
        sighash_type: Sighash,
    ) -> Result<Hash256, SighashError> {
        let annex = annex.map(validate_annex).transpose()?;
        let ty_byte = sighash_type.to_u8();
        let base = ty_byte & 0x03;

        let total = self.tx.input_count();
        if input_index >= total {
            return Err(SighashError::InputOutOfRange {
                index: input_index,
                total,
            });
        }
        if prevouts.len() != total {
            return Err(SighashError::PrevoutsLength {
                provided: prevouts.len(),
                expected: total,
            });
        }
        if base == 0x03 && input_index >= self.tx.output_count() {
            return Err(SighashError::SingleMissingOutput {
                input_index,
                outputs_length: self.tx.output_count(),
            });
        }
        let is_anyone_can_pay = ty_byte & 0x80 != 0;

        let mut engine = tag_engine(b"TapSighash");
        let writer = &mut Sha256Sink(&mut engine);
        writer.write_all(&[0x00]);
        writer.write_all(&[ty_byte]);
        writer.write_all(&self.tx.version().to_le_bytes());
        writer.write_all(&self.tx.lock_time().to_consensus().to_le_bytes());
        if !is_anyone_can_pay {
            writer.write_all(&self.prevouts().to_le_bytes());
            writer.write_all(&self.taproot_amounts(prevouts).to_le_bytes());
            writer.write_all(&self.taproot_scriptpubkeys(prevouts).to_le_bytes());
            writer.write_all(&self.sequences().to_le_bytes());
        }
        if base != 0x02 && base != 0x03 {
            writer.write_all(&self.outputs().to_le_bytes());
        }
        let mut spend_type = 0_u8;
        if annex.is_some() {
            spend_type |= 1;
        }
        if leaf_hash_code_separator.is_some() {
            spend_type |= 2;
        }
        writer.write_all(&[spend_type]);
        if is_anyone_can_pay {
            self.tx.input_outpoint(input_index).consensus_encode(writer);
            let prevout = prevouts
                .get(input_index)
                .ok_or(SighashError::PrevoutsIndex { index: input_index })?;
            writer.write_all(&prevout.value.to_le_bytes());
            write_script(writer, &prevout.script_pubkey);
            writer.write_all(&self.tx.input_sequence(input_index).to_le_bytes());
        } else {
            let input_index =
                u32::try_from(input_index).unwrap_or_else(|_| unreachable!("input index fits u32"));
            writer.write_all(&input_index.to_le_bytes());
        }
        if let Some(annex) = annex {
            let annex_len = varint::encode(compact_len(annex.len()));
            writer.write_all(&sha256_parts(&[annex_len.as_slice(), annex]));
        }
        if base == 0x03 {
            let output_hash = sha256_over(|w| self.tx.encode_output(input_index, w));
            writer.write_all(&output_hash.to_le_bytes());
        }
        if let Some((leaf_hash, code_separator_position)) = leaf_hash_code_separator {
            writer.write_all(leaf_hash.as_byte_array());
            writer.write_all(&[0x00]);
            writer.write_all(&code_separator_position.to_le_bytes());
        }

        Ok(Hash256::from_le_bytes(&engine.finalize().into()))
    }

    fn prevouts(&self) -> Hash256 {
        *self.prevouts.get_or_init(|| {
            sha256_over(|writer| {
                for i in 0..self.tx.input_count() {
                    self.tx.input_outpoint(i).consensus_encode(writer);
                }
            })
        })
    }

    fn taproot_amounts(&self, prevouts: &[TxOut]) -> Hash256 {
        *self.taproot_amounts.get_or_init(|| {
            sha256_over(|writer| {
                for prevout in prevouts {
                    writer.write_all(&prevout.value.to_le_bytes());
                }
            })
        })
    }

    fn taproot_scriptpubkeys(&self, prevouts: &[TxOut]) -> Hash256 {
        *self.taproot_scriptpubkeys.get_or_init(|| {
            sha256_over(|writer| {
                for prevout in prevouts {
                    write_script(writer, &prevout.script_pubkey);
                }
            })
        })
    }

    fn sequences(&self) -> Hash256 {
        *self.sequences.get_or_init(|| {
            sha256_over(|writer| {
                for i in 0..self.tx.input_count() {
                    writer.write_all(&self.tx.input_sequence(i).to_le_bytes());
                }
            })
        })
    }

    fn outputs(&self) -> Hash256 {
        *self.outputs.get_or_init(|| {
            sha256_over(|writer| {
                for i in 0..self.tx.output_count() {
                    self.tx.encode_output(i, writer);
                }
            })
        })
    }
}

impl Sighash {
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Default => 0x00,
            Self::All => 0x01,
            Self::None => 0x02,
            Self::Single => 0x03,
            Self::AllAnyoneCanPay => 0x81,
            Self::NoneAnyoneCanPay => 0x82,
            Self::SingleAnyoneCanPay => 0x83,
        }
    }

    pub const fn from_consensus_u8(byte: u8) -> Result<Self, SighashError> {
        match byte {
            0x00 => Ok(Self::Default),
            0x01 => Ok(Self::All),
            0x02 => Ok(Self::None),
            0x03 => Ok(Self::Single),
            0x81 => Ok(Self::AllAnyoneCanPay),
            0x82 => Ok(Self::NoneAnyoneCanPay),
            0x83 => Ok(Self::SingleAnyoneCanPay),
            _ => Err(SighashError::UnknownType(byte)),
        }
    }

    const fn to_ecdsa(self) -> Result<EcdsaType, SighashError> {
        match self {
            Self::All => Ok(EcdsaType::All),
            Self::None => Ok(EcdsaType::None),
            Self::Single => Ok(EcdsaType::Single),
            Self::AllAnyoneCanPay => Ok(EcdsaType::AllAnyoneCanPay),
            Self::NoneAnyoneCanPay => Ok(EcdsaType::NoneAnyoneCanPay),
            Self::SingleAnyoneCanPay => Ok(EcdsaType::SingleAnyoneCanPay),
            Self::Default => Err(SighashError::DefaultOnlyTaproot),
        }
    }
}

// SCR-03
#[must_use]
pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> Hash256 {
    let len = varint::encode(compact_len(script.len()));
    tagged_hash_parts(b"TapLeaf", &[&[leaf_version][..], len.as_slice(), script])
}

fn validate_annex(bytes: &[u8]) -> Result<&[u8], SighashError> {
    match bytes.split_first() {
        None => Err(SighashError::InvalidAnnex(AnnexError::Empty)),
        Some((&first, _)) if first != 0x50 => {
            Err(SighashError::InvalidAnnex(AnnexError::InvalidFirstByte))
        }
        Some((_, _)) => Ok(bytes),
    }
}

const fn uint256_one() -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[0] = 1;
    Hash256::from_le_bytes(&bytes)
}

fn sha256_over(encode: impl FnOnce(&mut Sha256Sink<'_>)) -> Hash256 {
    let mut engine = Sha256::new();
    let writer = &mut Sha256Sink(&mut engine);
    encode(writer);
    let first = engine.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&first);
    Hash256::from_le_bytes(&out)
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut engine = Sha256::new();
    for part in parts {
        Digest::update(&mut engine, part);
    }
    engine.finalize().into()
}

fn hash_digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hash_feed(engine: &mut Sha256, data: &[u8]) {
    Digest::update(engine, data);
}

fn hash_finish(engine: Sha256) -> [u8; 32] {
    engine.finalize().into()
}

fn init_tag_engine(tag: &[u8]) -> Sha256 {
    let tag_hash = hash_digest(tag);
    let mut engine = Sha256::new();
    hash_feed(&mut engine, &tag_hash);
    hash_feed(&mut engine, &tag_hash);
    engine
}

static TAPLEAF_ENGINE: LazyLock<Sha256> = LazyLock::new(|| init_tag_engine(b"TapLeaf"));
static TAPBRANCH_ENGINE: LazyLock<Sha256> = LazyLock::new(|| init_tag_engine(b"TapBranch"));
static TAPTWEAK_ENGINE: LazyLock<Sha256> = LazyLock::new(|| init_tag_engine(b"TapTweak"));
static TAPSIGHASH_ENGINE: LazyLock<Sha256> = LazyLock::new(|| init_tag_engine(b"TapSighash"));

fn tag_engine(tag: &[u8]) -> Sha256 {
    match tag {
        b"TapLeaf" => TAPLEAF_ENGINE.clone(),
        b"TapBranch" => TAPBRANCH_ENGINE.clone(),
        b"TapTweak" => TAPTWEAK_ENGINE.clone(),
        b"TapSighash" => TAPSIGHASH_ENGINE.clone(),
        _ => init_tag_engine(tag),
    }
}

// SCR-03
fn tagged_hash_parts(tag: &[u8], parts: &[&[u8]]) -> Hash256 {
    let mut engine = tag_engine(tag);
    for part in parts {
        hash_feed(&mut engine, part);
    }
    Hash256::from_le_bytes(&hash_finish(engine))
}

#[cfg(any(test, kani))]
fn tagged_hash(tag: &[u8], msg: &[u8]) -> Hash256 {
    tagged_hash_parts(tag, &[msg])
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions")]

    use super::{
        CODESEPARATOR_POSITION, Sighash, SighashCache, SighashError, TAPSCRIPT_LEAF_VERSION,
        compact_len, tagged_hash, tapleaf_hash,
    };
    use crate::primitives::{Hash256, OutPoint, Tx, Txid, varint};

    fn pin(hex: &str) -> Hash256 {
        Hash256::from_str_be(hex).expect("pinned hash hex")
    }

    #[test]
    fn tapleaf_hash_streaming_matches_concatenation_form() {
        for len in [0, 1, 10, 32, 100, 1000] {
            let script = vec![0x42_u8; len];
            let leaf_version = TAPSCRIPT_LEAF_VERSION;
            let streaming = tapleaf_hash(leaf_version, &script);
            let encoded_len = varint::encode(compact_len(script.len()));
            let msg = [
                &[leaf_version][..],
                encoded_len.as_slice(),
                script.as_slice(),
            ]
            .concat();
            let oracle = tagged_hash(b"TapLeaf", &msg);
            assert_eq!(streaming, oracle);
        }
    }

    #[test]
    fn tapleaf_hash_matches_bip341_wallet_vectors() {
        let vectors = [
            (
                0xc0_u8,
                "20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac",
                "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
            ),
            (
                0xfa_u8,
                "06424950333431",
                "f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a",
            ),
            (
                0xc0_u8,
                "20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac",
                "8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7",
            ),
        ];
        for (leaf_version, script_hex, leaf_hash_hex) in vectors {
            let script = crate::primitives::hex::hex_decode(script_hex).expect("vector script hex");
            let leaf_hash = Hash256::from_le_bytes(
                &crate::primitives::hex::hex_decode_array::<32>(leaf_hash_hex)
                    .expect("vector leaf hash hex"),
            );
            assert_eq!(tapleaf_hash(leaf_version, &script), leaf_hash);
        }
    }

    fn synthetic_tx(output_count: usize) -> Tx {
        let input = crate::primitives::TxIn {
            previous_output: OutPoint::new(Txid(Hash256::default()), 0xffff_ffff),
            script_sig: crate::primitives::Script::new(),
            sequence: crate::primitives::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: crate::primitives::Witness::new(),
        };
        let mut outputs = Vec::new();
        for value in 0..output_count {
            outputs.push(crate::primitives::TxOut {
                value: crate::primitives::Amount::from_sat(
                    1_000 + u64::try_from(value).unwrap_or_else(|_| unreachable!("small count")),
                ),
                script_pubkey: crate::primitives::Script::new(),
            });
        }
        Tx {
            version: 2,
            inputs: vec![input],
            outputs,
            lock_time: crate::primitives::LockTime::ZERO,
        }
    }

    #[test]
    fn legacy_sighash_pins_all_ecdsa_modes() {
        let tx = synthetic_tx(2);
        let script = vec![0x51_u8];
        let pins = [
            (
                Sighash::All,
                "4127751e4f67b766f2e28b9cb14a0e7dea69ca90f7e41d1290cd1b6b8ba26c13",
            ),
            (
                Sighash::None,
                "3f42e7611510fd8f5010f0214d2de59b3ffe62b69c9179b6f908620eb0be844c",
            ),
            (
                Sighash::Single,
                "e142c8e6e225a647d83a45b1b37a9a37a51aecbee8a3ba79932cf093f76bf9ba",
            ),
            (
                Sighash::AllAnyoneCanPay,
                "d11d53d12184f74612a4496afb3e79c6cb5f162740a55ccc1175c386ffdc6f91",
            ),
            (
                Sighash::NoneAnyoneCanPay,
                "38b9b28bda7132027812bb53b4886b8893151604e85115fb4d029d8ad071c66b",
            ),
            (
                Sighash::SingleAnyoneCanPay,
                "841875c2ad3cfb401234594333ff42957782a7a81be5ac482067e9e9f9802c36",
            ),
        ];
        for (mode, expected) in pins {
            assert_eq!(
                SighashCache::new(&tx).legacy_signature_hash(0, &script, u32::from(mode.to_u8())),
                Ok(pin(expected))
            );
        }
    }

    #[test]
    fn bip143_sighash_pins_single() {
        let tx = synthetic_tx(2);
        let script = vec![0x51_u8, 0x51];
        assert_eq!(
            SighashCache::new(&tx).segwit_v0_signature_hash(
                0,
                &script,
                crate::primitives::Amount::from_sat(50_000),
                Sighash::Single
            ),
            Ok(pin(
                "c9bb107a16a13d1a8ad4ebc540978164a7d92b4a26d388d26fa8eed79e10ebec"
            ))
        );
    }

    #[test]
    fn bip341_key_path_and_bip342_script_path_pins() {
        let tx = synthetic_tx(2);
        let prevouts = vec![crate::primitives::TxOut {
            value: crate::primitives::Amount::from_sat(50_000),
            script_pubkey: crate::primitives::Script::new(),
        }];
        assert_eq!(
            SighashCache::new(&tx).taproot_signature_hash(
                0,
                &prevouts,
                None,
                None,
                Sighash::AllAnyoneCanPay
            ),
            Ok(pin(
                "8910eff2c9430e82893c47e1ba29da7ff76285dcb7a386bb9cbdd04fc97b8c8f"
            ))
        );
        let leaf = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x51]);
        assert_eq!(
            leaf,
            pin("75d68237360f5032d84419d0d32e2061cbc7ce286c58e7846ab291f707215ba8")
        );
        assert_eq!(
            SighashCache::new(&tx).taproot_signature_hash(
                0,
                &prevouts,
                None,
                Some((leaf, CODESEPARATOR_POSITION)),
                Sighash::Default
            ),
            Ok(pin(
                "4cc7918733b1c9abd997206fac92d03183ec712d059dd5da5bd099e39b66a1d6"
            ))
        );
    }

    #[test]
    fn legacy_sighash_reports_out_of_range_input() {
        let tx = synthetic_tx(1);

        assert!(matches!(
            SighashCache::new(&tx).legacy_signature_hash(999, &[], u32::from(Sighash::All.to_u8())),
            Err(SighashError::InputOutOfRange {
                index: 999,
                total: 1
            })
        ));
    }

    #[test]
    fn bip143_rejects_default_sighash_without_panicking() {
        let tx = synthetic_tx(1);

        assert_eq!(
            SighashCache::new(&tx).segwit_v0_signature_hash(
                0,
                &[],
                crate::primitives::Amount::from_sat(50_000),
                Sighash::Default
            ),
            Err(SighashError::DefaultOnlyTaproot)
        );
    }

    #[test]
    fn taproot_sighash_reports_invalid_annex() {
        let tx = synthetic_tx(1);
        let prevouts = vec![crate::primitives::TxOut {
            value: crate::primitives::Amount::from_sat(50_000),
            script_pubkey: crate::primitives::Script::new(),
        }];

        assert!(matches!(
            SighashCache::new(&tx).taproot_signature_hash(
                0,
                &prevouts,
                Some(&[0x51]),
                None,
                Sighash::All
            ),
            Err(SighashError::InvalidAnnex(_))
        ));
    }

    #[test]
    fn from_consensus_u8_roundtrips_all_modes() {
        for mode in [
            Sighash::Default,
            Sighash::All,
            Sighash::None,
            Sighash::Single,
            Sighash::AllAnyoneCanPay,
            Sighash::NoneAnyoneCanPay,
            Sighash::SingleAnyoneCanPay,
        ] {
            assert_eq!(Sighash::from_consensus_u8(mode.to_u8()), Ok(mode));
        }
        assert_eq!(
            Sighash::from_consensus_u8(0xff),
            Err(SighashError::UnknownType(0xff))
        );
    }

    #[test]
    fn legacy_masked_sighash_flags_pin_raw_wire_patterns() {
        let tx = synthetic_tx(2);
        let script = vec![0x51_u8, 0x52, 0x53];
        let flags: [(u32, &str); 6] = [
            (
                u32::from_le_bytes((-1_391_424_484_i32).to_le_bytes()),
                "33ed02ca66219e1b2fc5d7f7c0496e1c7792ab8853364a4853327bd13168e8a3",
            ),
            (
                1_864_164_639,
                "93c71c8d797406ebf8d69105ba692f13ea3a798359daaa5bab9283d8a86a9c92",
            ),
            (
                131,
                "c0fc189225ee44e546b8b79aade907bd11eabb3bb716b7a66400416de498672b",
            ),
            (
                0x1f | 0x80 | 0x40,
                "3251b8b07c14f20cbff5a9ad80e7001ad1819fb3ad55403336aeaeb763a8c015",
            ),
            (
                0xffff_ffbf,
                "e5bf6aaad9765706722d08a3b82cb6eea9f10d0b8acd8f882bf35e96cd1c9476",
            ),
            (
                0x83 | 0x40,
                "c0a87d511cd13c9346d2113f6b08f152eaa100b1d0b1f48dbc76047d58660d6e",
            ),
        ];
        for (flag, expected) in flags {
            assert_eq!(
                SighashCache::new(&tx)
                    .legacy_signature_hash(0, &script, flag)
                    .expect("native legacy sighash"),
                pin(expected)
            );
        }
    }
}
