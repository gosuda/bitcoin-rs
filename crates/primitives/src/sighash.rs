//! Native signature-hash computation: legacy, BIP143 (segwit v0), and BIP341/342 (taproot).
//!
//! `SighashCache` holds a transaction reference plus lazily computed midstates. The
//! algorithms are bug-for-bug compatible with Bitcoin Core's `interpreter.cpp`
//! (`SignatureHash`, `SignatureHashSchnorr`) and byte-identical with the `bitcoin`
//! crate's `SighashCache`, which this crate's tests use as the differential oracle.

use std::io::Write as _;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    Hash256, Tx, TxOut,
    encode::{
        ConsensusEncode, Sha256Writer, compact_len, finalize_double_sha256, write_compact,
        write_script,
    },
    varint,
};

/// Position marker used when no `OP_CODESEPARATOR` executed before the opcodes being signed.
pub const CODESEPARATOR_POSITION: u32 = 0xFFFF_FFFF;

/// BIP342 leaf version byte for tapscript leaves.
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// Standard Bitcoin signature hash modes used by legacy, segwit, and taproot signing.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Sighash {
    /// `SIGHASH_ALL`.
    All,
    /// `SIGHASH_NONE`.
    None,
    /// `SIGHASH_SINGLE`.
    Single,
    /// `SIGHASH_ALL | SIGHASH_ANYONECANPAY`.
    AllAnyoneCanPay,
    /// `SIGHASH_NONE | SIGHASH_ANYONECANPAY`.
    NoneAnyoneCanPay,
    /// `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`.
    SingleAnyoneCanPay,
    /// `SIGHASH_DEFAULT`, valid for taproot only.
    Default,
}

/// Errors returned while computing signature hashes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SighashError {
    /// The requested transaction input does not exist.
    #[error("input index {index} out of range for {total} inputs")]
    InputOutOfRange {
        /// Requested input index.
        index: usize,
        /// Number of transaction inputs.
        total: usize,
    },
    /// `SIGHASH_DEFAULT` is valid for taproot only.
    #[error("SIGHASH_DEFAULT is valid only for taproot")]
    DefaultOnlyTaproot,
    /// Taproot annex bytes failed BIP341 validation.
    #[error("invalid taproot annex: {0}")]
    InvalidAnnex(#[source] AnnexError),
    /// Taproot `SIGHASH_SINGLE` requires an output at the same index as the input.
    #[error(
        "sighash single requires output at input index {input_index}; outputs length {outputs_length}"
    )]
    SingleMissingOutput {
        /// Input index being signed.
        input_index: usize,
        /// Number of transaction outputs.
        outputs_length: usize,
    },
    /// Taproot prevout count must match the transaction input count.
    #[error("taproot prevouts length {provided} does not match input count {expected}")]
    PrevoutsLength {
        /// Supplied prevout count.
        provided: usize,
        /// Transaction input count.
        expected: usize,
    },
    /// Taproot prevout lookup failed for the requested index.
    #[error("taproot prevout at index {index} unavailable")]
    PrevoutsIndex {
        /// Supplied prevout index.
        index: usize,
    },
    /// The one-byte consensus form does not name a known sighash type.
    #[error("unknown sighash type byte {0:#04x}")]
    UnknownType(u8),
}

/// BIP341 annex validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnnexError {
    /// The annex is empty.
    #[error("annex is empty")]
    Empty,
    /// The annex does not start with the mandatory 0x50 prefix byte.
    #[error("annex must start with the 0x50 prefix byte")]
    InvalidFirstByte,
}

/// The masked base type of a legacy sighash flag (Core's `nHashType & 0x1f | 0x80` mask).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum EcdsaType {
    All,
    None,
    Single,
    AllAnyoneCanPay,
    NoneAnyoneCanPay,
    SingleAnyoneCanPay,
}

impl EcdsaType {
    /// Masks a raw 32-bit sighash flag down to the representable base type, mirroring
    /// Core's `SignatureHash`: stray middle bits are ignored, the ANYONECANPAY bit and
    /// the `0x1f` base bits decide.
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

/// Lazily cached signature hashes for one transaction.
///
/// The taproot amount/scriptPubKey midstates assume the same prevout set is supplied to
/// every call on this cache (the same assumption the `bitcoin` crate's cache makes);
/// construct a fresh cache when the prevout set changes.
pub struct SighashCache<'t> {
    tx: &'t Tx,
    segwit_prevouts: Option<Hash256>,
    segwit_sequences: Option<Hash256>,
    segwit_outputs: Option<Hash256>,
    taproot_prevouts: Option<Hash256>,
    taproot_amounts: Option<Hash256>,
    taproot_scriptpubkeys: Option<Hash256>,
    taproot_sequences: Option<Hash256>,
    taproot_outputs: Option<Hash256>,
}

impl<'t> SighashCache<'t> {
    /// Constructs a cache over `tx` with all midstates uninitialized.
    #[must_use]
    pub fn new(tx: &'t Tx) -> Self {
        Self {
            tx,
            segwit_prevouts: None,
            segwit_sequences: None,
            segwit_outputs: None,
            taproot_prevouts: None,
            taproot_amounts: None,
            taproot_scriptpubkeys: None,
            taproot_sequences: None,
            taproot_outputs: None,
        }
    }

    /// Computes the pre-segwit legacy signature hash for `sighash_type` as a raw 32-bit
    /// flag. Stray middle bits are ignored when classifying (Core's `& 0x1f | 0x80` mask)
    /// but the raw value is appended to the hash. The `SIGHASH_SINGLE` bug is reproduced:
    /// when the masked type is SINGLE and `input_index` has no matching output, the
    /// uint256 value 1 is returned.
    pub fn legacy_signature_hash(
        &self,
        input_index: usize,
        script_code: &[u8],
        sighash_type: u32,
    ) -> Result<Hash256, SighashError> {
        let total = self.tx.inputs.len();
        let input = self
            .tx
            .inputs
            .get(input_index)
            .ok_or(SighashError::InputOutOfRange {
                index: input_index,
                total,
            })?;
        let ty = EcdsaType::from_consensus(sighash_type);
        if ty.is_single() && input_index >= self.tx.outputs.len() {
            return Ok(uint256_one());
        }

        let mut engine = Sha256::new();
        let writer = &mut Sha256Writer(&mut engine);

        let () = writer
            .write_all(&self.tx.version.to_le_bytes())
            .and_then(|()| {
                if ty.is_anyone_can_pay() {
                    write_compact(writer, 1)?;
                    encode_legacy_input(writer, input, script_code, input.sequence)
                } else {
                    write_compact(writer, compact_len(total))?;
                    for (n, txin) in self.tx.inputs.iter().enumerate() {
                        let sequence = if n != input_index && (ty.is_single() || ty.is_none()) {
                            0
                        } else {
                            txin.sequence
                        };
                        let script: &[u8] = if n == input_index { script_code } else { &[] };
                        encode_legacy_input(writer, txin, script, sequence)?;
                    }
                    Ok(())
                }
            })
            .and_then(|()| match ty {
                EcdsaType::All | EcdsaType::AllAnyoneCanPay => {
                    write_compact(writer, compact_len(self.tx.outputs.len()))?;
                    for output in &self.tx.outputs {
                        output.consensus_encode(writer)?;
                    }
                    Ok(())
                }
                EcdsaType::Single | EcdsaType::SingleAnyoneCanPay => {
                    write_compact(writer, compact_len(input_index + 1))?;
                    for (n, output) in self.tx.outputs.iter().enumerate().take(input_index + 1) {
                        if n == input_index {
                            output.consensus_encode(writer)?;
                        } else {
                            // Core blanks non-matching outputs to value -1 with an empty script.
                            writer.write_all(&u64::MAX.to_le_bytes())?;
                            write_compact(writer, 0)?;
                        }
                    }
                    Ok(())
                }
                _ => write_compact(writer, 0),
            })
            .and_then(|()| writer.write_all(&self.tx.lock_time.to_le_bytes()))
            .and_then(|()| writer.write_all(&sighash_type.to_le_bytes()))
            .unwrap_or_else(|error| unreachable!("sha256 writer is infallible: {error}"));

        Ok(finalize_double_sha256(engine))
    }

    /// Computes the BIP143 segwit-v0 signature hash (p2wpkh and p2wsh alike: the caller
    /// supplies the witness script / p2wpkh template as `script_code`).
    pub fn segwit_v0_signature_hash(
        &mut self,
        input_index: usize,
        script_code: &[u8],
        value: u64,
        sighash_type: Sighash,
    ) -> Result<Hash256, SighashError> {
        let ty = sighash_type.to_ecdsa()?;
        let total = self.tx.inputs.len();
        let input = self
            .tx
            .inputs
            .get(input_index)
            .ok_or(SighashError::InputOutOfRange {
                index: input_index,
                total,
            })?;

        let zero = Hash256::default();
        let prevouts_hash = if ty.is_anyone_can_pay() {
            zero
        } else {
            self.segwit_prevouts()
        };
        let sequences_hash = if ty.is_anyone_can_pay() || ty.is_single() || ty.is_none() {
            zero
        } else {
            self.segwit_sequences()
        };

        let outputs_hash = if !ty.is_single() && !ty.is_none() {
            self.segwit_outputs()
        } else if ty.is_single() {
            match self.tx.outputs.get(input_index) {
                Some(output) => {
                    let mut single = Sha256::new();
                    let single_writer = &mut Sha256Writer(&mut single);
                    output
                        .consensus_encode(single_writer)
                        .unwrap_or_else(|error| {
                            unreachable!("sha256 writer is infallible: {error}")
                        });
                    finalize_double_sha256(single)
                }
                // BIP143 leaves this case undefined; Core rejects the signature while the
                // rust-bitcoin oracle emits the zero hash. Either way no signature can
                // verify, so we mirror the oracle's zero hash.
                None => zero,
            }
        } else {
            zero
        };

        let mut engine = Sha256::new();
        let writer = &mut Sha256Writer(&mut engine);
        let () = writer
            .write_all(&self.tx.version.to_le_bytes())
            .and_then(|()| writer.write_all(prevouts_hash.as_byte_array()))
            .and_then(|()| writer.write_all(sequences_hash.as_byte_array()))
            .and_then(|()| input.previous_output.consensus_encode(writer))
            .and_then(|()| write_script(writer, script_code))
            .and_then(|()| writer.write_all(&value.to_le_bytes()))
            .and_then(|()| writer.write_all(&input.sequence.to_le_bytes()))
            .and_then(|()| writer.write_all(outputs_hash.as_byte_array()))
            .and_then(|()| writer.write_all(&self.tx.lock_time.to_le_bytes()))
            .and_then(|()| writer.write_all(&ty.to_u32().to_le_bytes()))
            .unwrap_or_else(|error| unreachable!("sha256 writer is infallible: {error}"));

        Ok(finalize_double_sha256(engine))
    }

    /// Computes the BIP341 taproot signature hash. `leaf_hash_code_separator` is `None`
    /// for key-path spends and `Some((leaf_hash, code_separator_position))` for script
    /// path spends (BIP342). The tagged hash includes Core's zero epoch byte.
    pub fn taproot_signature_hash(
        &mut self,
        input_index: usize,
        prevouts: &[TxOut],
        annex: Option<&[u8]>,
        leaf_hash_code_separator: Option<(Hash256, u32)>,
        sighash_type: Sighash,
    ) -> Result<Hash256, SighashError> {
        let annex = annex.map(validate_annex).transpose()?;
        let ty_byte = sighash_type.to_u8();
        let base = ty_byte & 0x03;

        let total = self.tx.inputs.len();
        let input = self
            .tx
            .inputs
            .get(input_index)
            .ok_or(SighashError::InputOutOfRange {
                index: input_index,
                total,
            })?;
        if prevouts.len() != total {
            return Err(SighashError::PrevoutsLength {
                provided: prevouts.len(),
                expected: total,
            });
        }
        if base == 0x03 && input_index >= self.tx.outputs.len() {
            return Err(SighashError::SingleMissingOutput {
                input_index,
                outputs_length: self.tx.outputs.len(),
            });
        }
        let is_anyone_can_pay = ty_byte & 0x80 != 0;

        let mut msg = Vec::with_capacity(64 + total * 40 + self.tx.outputs.len() * 16);
        msg.push(0x00); // epoch (Core: SignatureHashSchnorr epoch 0)
        msg.push(ty_byte);
        msg.extend_from_slice(&self.tx.version.to_le_bytes());
        msg.extend_from_slice(&self.tx.lock_time.to_le_bytes());
        if !is_anyone_can_pay {
            msg.extend_from_slice(&self.taproot_prevouts().to_le_bytes());
            msg.extend_from_slice(&self.taproot_amounts(prevouts).to_le_bytes());
            msg.extend_from_slice(&self.taproot_scriptpubkeys(prevouts).to_le_bytes());
            msg.extend_from_slice(&self.taproot_sequences().to_le_bytes());
        }
        if base != 0x02 && base != 0x03 {
            msg.extend_from_slice(&self.taproot_outputs().to_le_bytes());
        }
        let mut spend_type = 0_u8;
        if annex.is_some() {
            spend_type |= 1;
        }
        if leaf_hash_code_separator.is_some() {
            spend_type |= 2;
        }
        msg.push(spend_type);
        if is_anyone_can_pay {
            input
                .previous_output
                .consensus_encode(&mut msg)
                .unwrap_or_else(|error| unreachable!("Vec write is infallible: {error}"));
            let prevout = prevouts
                .get(input_index)
                .ok_or(SighashError::PrevoutsIndex { index: input_index })?;
            msg.extend_from_slice(&prevout.value.to_le_bytes());
            write_script(&mut msg, &prevout.script_pubkey)
                .unwrap_or_else(|error| unreachable!("Vec write is infallible: {error}"));
            msg.extend_from_slice(&input.sequence.to_le_bytes());
        } else {
            let input_index =
                u32::try_from(input_index).unwrap_or_else(|_| unreachable!("input index fits u32"));
            msg.extend_from_slice(&input_index.to_le_bytes());
        }
        if let Some(annex) = annex {
            let annex_len = varint::encode(compact_len(annex.len())).as_slice().to_vec();
            msg.extend_from_slice(&sha256_parts(&[&annex_len, annex]));
        }
        if base == 0x03 {
            let output = &self.tx.outputs[input_index];
            msg.extend_from_slice(&sha256_parts(&[&crate::encode::consensus_bytes(output)]));
        }
        if let Some((leaf_hash, code_separator_position)) = leaf_hash_code_separator {
            msg.extend_from_slice(leaf_hash.as_byte_array());
            msg.push(0x00); // key version 0
            msg.extend_from_slice(&code_separator_position.to_le_bytes());
        }

        Ok(tagged_hash(b"TapSighash", &msg))
    }

    fn segwit_prevouts(&mut self) -> Hash256 {
        let tx = self.tx;
        *self.segwit_prevouts.get_or_insert_with(|| {
            double_sha256_over(|writer| {
                for input in &tx.inputs {
                    input.previous_output.consensus_encode(writer)?;
                }
                Ok(())
            })
        })
    }

    fn segwit_sequences(&mut self) -> Hash256 {
        let tx = self.tx;
        *self.segwit_sequences.get_or_insert_with(|| {
            double_sha256_over(|writer| {
                for input in &tx.inputs {
                    writer.write_all(&input.sequence.to_le_bytes())?;
                }
                Ok(())
            })
        })
    }

    fn segwit_outputs(&mut self) -> Hash256 {
        let tx = self.tx;
        *self.segwit_outputs.get_or_insert_with(|| {
            double_sha256_over(|writer| {
                for output in &tx.outputs {
                    output.consensus_encode(writer)?;
                }
                Ok(())
            })
        })
    }

    fn taproot_prevouts(&mut self) -> Hash256 {
        let tx = self.tx;
        *self.taproot_prevouts.get_or_insert_with(|| {
            sha256_over(|writer| {
                for input in &tx.inputs {
                    input.previous_output.consensus_encode(writer)?;
                }
                Ok(())
            })
        })
    }

    fn taproot_amounts(&mut self, prevouts: &[TxOut]) -> Hash256 {
        *self.taproot_amounts.get_or_insert_with(|| {
            sha256_over(|writer| {
                for prevout in prevouts {
                    writer.write_all(&prevout.value.to_le_bytes())?;
                }
                Ok(())
            })
        })
    }

    fn taproot_scriptpubkeys(&mut self, prevouts: &[TxOut]) -> Hash256 {
        *self.taproot_scriptpubkeys.get_or_insert_with(|| {
            sha256_over(|writer| {
                for prevout in prevouts {
                    write_script(writer, &prevout.script_pubkey)?;
                }
                Ok(())
            })
        })
    }

    fn taproot_sequences(&mut self) -> Hash256 {
        let tx = self.tx;
        *self.taproot_sequences.get_or_insert_with(|| {
            sha256_over(|writer| {
                for input in &tx.inputs {
                    writer.write_all(&input.sequence.to_le_bytes())?;
                }
                Ok(())
            })
        })
    }

    fn taproot_outputs(&mut self) -> Hash256 {
        let tx = self.tx;
        *self.taproot_outputs.get_or_insert_with(|| {
            sha256_over(|writer| {
                for output in &tx.outputs {
                    output.consensus_encode(writer)?;
                }
                Ok(())
            })
        })
    }
}

impl Sighash {
    /// Computes the pre-segwit legacy signature hash.
    pub fn compute_legacy(
        tx: &Tx,
        input_idx: usize,
        script_code: &[u8],
        sighash_type: Self,
    ) -> Result<Hash256, SighashError> {
        SighashCache::new(tx).legacy_signature_hash(
            input_idx,
            script_code,
            u32::from(sighash_type.to_u8()),
        )
    }

    /// Computes the BIP143 segwit-v0 signature hash.
    pub fn compute_bip143(
        tx: &Tx,
        input_idx: usize,
        script_code: &[u8],
        value: u64,
        sighash_type: Self,
    ) -> Result<Hash256, SighashError> {
        SighashCache::new(tx).segwit_v0_signature_hash(input_idx, script_code, value, sighash_type)
    }

    /// Computes the BIP341 taproot signature hash for key-path or script-path spends.
    pub fn compute_bip341(
        tx: &Tx,
        input_idx: usize,
        prevouts: &[TxOut],
        sighash_type: Self,
        leaf_hash: Option<Hash256>,
        annex: Option<&[u8]>,
    ) -> Result<Hash256, SighashError> {
        SighashCache::new(tx).taproot_signature_hash(
            input_idx,
            prevouts,
            annex,
            leaf_hash.map(|leaf_hash| (leaf_hash, CODESEPARATOR_POSITION)),
            sighash_type,
        )
    }

    /// Computes the BIP342 tapscript signature hash.
    pub fn compute_bip342(
        tx: &Tx,
        input_idx: usize,
        prevouts: &[TxOut],
        sighash_type: Self,
        leaf_hash: Hash256,
        annex: Option<&[u8]>,
    ) -> Result<Hash256, SighashError> {
        Self::compute_bip341(
            tx,
            input_idx,
            prevouts,
            sighash_type,
            Some(leaf_hash),
            annex,
        )
    }

    /// Returns the consensus byte for the sighash mode.
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

    /// Parses the one-byte consensus form of a sighash mode (BIP341).
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

/// Computes the BIP341 tapleaf hash for a leaf script at `leaf_version`
/// (use [`TAPSCRIPT_LEAF_VERSION`] for BIP342 tapscript).
#[must_use]
pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> Hash256 {
    let len = varint::encode(compact_len(script.len()))
        .as_slice()
        .to_vec();
    let msg = [&[leaf_version][..], len.as_slice(), script].concat();
    tagged_hash(b"TapLeaf", &msg)
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

fn encode_legacy_input(
    writer: &mut Sha256Writer<'_>,
    input: &crate::TxIn,
    script: &[u8],
    sequence: u32,
) -> std::io::Result<()> {
    input.previous_output.consensus_encode(writer)?;
    write_script(writer, script)?;
    writer.write_all(&sequence.to_le_bytes())
}

fn sha256_over(encode: impl FnOnce(&mut Sha256Writer<'_>) -> std::io::Result<()>) -> Hash256 {
    let mut engine = Sha256::new();
    let writer = &mut Sha256Writer(&mut engine);
    encode(writer).unwrap_or_else(|error| unreachable!("sha256 writer is infallible: {error}"));
    let first = engine.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&first);
    Hash256::from_le_bytes(&out)
}

fn double_sha256_over(
    encode: impl FnOnce(&mut Sha256Writer<'_>) -> std::io::Result<()>,
) -> Hash256 {
    let mut engine = Sha256::new();
    let writer = &mut Sha256Writer(&mut engine);
    encode(writer).unwrap_or_else(|error| unreachable!("sha256 writer is infallible: {error}"));
    finalize_double_sha256(engine)
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut engine = Sha256::new();
    for part in parts {
        Digest::update(&mut engine, part);
    }
    engine.finalize().into()
}

fn tagged_hash(tag: &[u8], msg: &[u8]) -> Hash256 {
    let tag_hash = Sha256::digest(tag);
    let mut engine = Sha256::new();
    Digest::update(&mut engine, tag_hash);
    Digest::update(&mut engine, tag_hash);
    Digest::update(&mut engine, msg);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&engine.finalize());
    Hash256::from_le_bytes(&out)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions")]
    use bitcoin::hashes::Hash as _;
    use bitcoin::sighash::{
        EcdsaSighashType, Prevouts, SighashCache as BitcoinCache, TapSighashType,
    };
    use bitcoin::{
        Amount, OutPoint as BitcoinOutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness, absolute,
    };

    use super::{
        CODESEPARATOR_POSITION, Sighash, SighashCache, SighashError, TAPSCRIPT_LEAF_VERSION,
        tapleaf_hash,
    };
    use crate::{Hash256, OutPoint, Tx, Txid};

    fn synthetic_tx(output_count: usize) -> Tx {
        let input = crate::TxIn {
            previous_output: OutPoint::new(Txid(Hash256::default()), 0xffff_ffff),
            script_sig: Vec::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME.to_consensus_u32(),
            witness: Vec::new(),
        };
        let mut outputs = Vec::new();
        for value in 0..output_count {
            outputs.push(crate::TxOut {
                value: 1_000 + u64::try_from(value).unwrap_or_else(|_| unreachable!("small count")),
                script_pubkey: Vec::new(),
            });
        }
        Tx {
            version: 2,
            inputs: vec![input],
            outputs,
            lock_time: 0,
        }
    }

    fn synthetic_bitcoin_tx(output_count: usize) -> Transaction {
        let input = TxIn {
            previous_output: BitcoinOutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        let mut outputs = Vec::new();
        for value in 0..output_count {
            outputs.push(TxOut {
                value: Amount::from_sat(
                    1_000
                        + u64::try_from(value)
                            .unwrap_or_else(|error| panic!("output count overflow: {error}")),
                ),
                script_pubkey: ScriptBuf::new(),
            });
        }
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![input],
            output: outputs,
        }
    }

    #[test]
    fn legacy_sighash_matches_bitcoin_cache_for_all_ecdsa_modes() {
        let tx = synthetic_tx(2);
        let script = vec![0x51_u8];
        let modes = [
            (Sighash::All, EcdsaSighashType::All),
            (Sighash::None, EcdsaSighashType::None),
            (Sighash::Single, EcdsaSighashType::Single),
            (
                Sighash::AllAnyoneCanPay,
                EcdsaSighashType::AllPlusAnyoneCanPay,
            ),
            (
                Sighash::NoneAnyoneCanPay,
                EcdsaSighashType::NonePlusAnyoneCanPay,
            ),
            (
                Sighash::SingleAnyoneCanPay,
                EcdsaSighashType::SinglePlusAnyoneCanPay,
            ),
        ];
        let bitcoin_tx = synthetic_bitcoin_tx(2);
        let bitcoin_cache = BitcoinCache::new(&bitcoin_tx);
        for (ours, bitcoin_ty) in modes {
            let expected = match bitcoin_cache.legacy_signature_hash(
                0,
                ScriptBuf::from_bytes(script.clone()).as_script(),
                bitcoin_ty.to_u32(),
            ) {
                Ok(hash) => Hash256::from_le_bytes(hash.as_byte_array()),
                Err(error) => panic!("fixture legacy sighash failed: {error}"),
            };
            assert_eq!(Sighash::compute_legacy(&tx, 0, &script, ours), Ok(expected));
        }
    }

    #[test]
    fn bip143_sighash_matches_bitcoin_cache() {
        let tx = synthetic_tx(2);
        let script = vec![0x51_u8, 0x51];
        let value = 50_000;
        let bitcoin_tx = synthetic_bitcoin_tx(2);
        let mut bitcoin_cache = BitcoinCache::new(&bitcoin_tx);
        let expected = match bitcoin_cache.p2wsh_signature_hash(
            0,
            ScriptBuf::from_bytes(script.clone()).as_script(),
            Amount::from_sat(value),
            EcdsaSighashType::Single,
        ) {
            Ok(hash) => Hash256::from_le_bytes(hash.as_byte_array()),
            Err(error) => panic!("fixture bip143 sighash failed: {error}"),
        };

        assert_eq!(
            Sighash::compute_bip143(&tx, 0, &script, value, Sighash::Single),
            Ok(expected)
        );
    }

    #[test]
    fn bip341_key_path_and_bip342_script_path_match_bitcoin_cache() {
        let tx = synthetic_tx(2);
        let prevouts = vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new(),
        }];
        let native_prevouts = vec![crate::TxOut {
            value: 50_000,
            script_pubkey: Vec::new(),
        }];
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let leaf_hash = script.tapscript_leaf_hash();

        let key_tx = synthetic_bitcoin_tx(2);
        let mut key_cache = BitcoinCache::new(&key_tx);
        let expected_key = match key_cache.taproot_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            None,
            None,
            TapSighashType::AllPlusAnyoneCanPay,
        ) {
            Ok(hash) => Hash256::from_le_bytes(hash.as_byte_array()),
            Err(error) => panic!("fixture taproot key sighash failed: {error}"),
        };
        assert_eq!(
            Sighash::compute_bip341(
                &tx,
                0,
                &native_prevouts,
                Sighash::AllAnyoneCanPay,
                None,
                None
            ),
            Ok(expected_key)
        );

        let script_tx = synthetic_bitcoin_tx(2);
        let mut script_cache = BitcoinCache::new(&script_tx);
        let expected_script = match script_cache.taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        ) {
            Ok(hash) => Hash256::from_le_bytes(hash.as_byte_array()),
            Err(error) => panic!("fixture tapscript sighash failed: {error}"),
        };
        let leaf_hash = Hash256::from_le_bytes(leaf_hash.as_byte_array());
        assert_eq!(
            tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x51]),
            leaf_hash,
            "native tapleaf hash must match the bitcoin crate"
        );
        assert_eq!(
            Sighash::compute_bip342(&tx, 0, &native_prevouts, Sighash::Default, leaf_hash, None),
            Ok(expected_script)
        );
        let _ = CODESEPARATOR_POSITION;
    }

    #[test]
    fn legacy_sighash_reports_out_of_range_input() {
        let tx = synthetic_tx(1);

        assert!(matches!(
            Sighash::compute_legacy(&tx, 999, &[], Sighash::All),
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
            Sighash::compute_bip143(&tx, 0, &[], 50_000, Sighash::Default),
            Err(SighashError::DefaultOnlyTaproot)
        );
    }

    #[test]
    fn taproot_sighash_reports_invalid_annex() {
        let tx = synthetic_tx(1);
        let prevouts = vec![crate::TxOut {
            value: 50_000,
            script_pubkey: Vec::new(),
        }];

        assert!(matches!(
            Sighash::compute_bip341(&tx, 0, &prevouts, Sighash::All, None, Some(&[0x51])),
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
    fn legacy_masked_sighash_flags_match_bitcoin_cache() {
        // Stray middle bits are masked away for classification but the raw value is
        // appended to the hash; Core's sighash.json exercises exactly these shapes.
        let tx = synthetic_tx(2);
        let bitcoin_tx = synthetic_bitcoin_tx(2);
        let script = vec![0x51_u8, 0x52, 0x53];
        // -1_391_424_484 truncated to its low 32 bits: a deliberately pathological
        // hash-type pattern (stray high bits set) exercised against the oracle.
        #[expect(
            clippy::as_conversions,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "the value is a raw 32-bit wire pattern; the truncating cast is the point"
        )]
        let flags: [u32; 6] = [
            (-1_391_424_484_i64) as u32,
            1_864_164_639,
            131,
            0x1f | 0x80 | 0x40, // stray 0x40 bit: classified ACP-ALL, raw appended
            0xffff_ffbf,        // stray bits, non-ACP: classified ALL
            0x83 | 0x40,
        ];
        for flag in flags {
            let bitcoin_cache = BitcoinCache::new(&bitcoin_tx);
            let expected = bitcoin_cache
                .legacy_signature_hash(0, ScriptBuf::from_bytes(script.clone()).as_script(), flag)
                .map_or_else(
                    |_| panic!("oracle legacy sighash must succeed for valid index"),
                    |hash| Hash256::from_le_bytes(hash.as_byte_array()),
                );
            assert_eq!(
                SighashCache::new(&tx)
                    .legacy_signature_hash(0, &script, flag)
                    .expect("native legacy sighash"),
                expected
            );
        }
    }
}
