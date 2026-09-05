//! Consensus encoding and hashing helpers for the native protocol types.
//!
//! `ConsensusEncode`/`ConsensusDecode` are the native consensus serialization:
//! segwit marker/flag handling and witness serialization follow BIP144, and
//! malformed input always yields a typed [`DecodeError`].

use std::io::{self, Write};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, varint};

/// `io::Write` sink that only accumulates the byte count.
pub(crate) struct CountWriter<'a>(pub(crate) &'a mut usize);

impl Write for CountWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        *self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `io::Write` adapter that streams bytes into a SHA-256 engine without allocating.
pub(crate) struct Sha256Writer<'a>(pub(crate) &'a mut Sha256);

impl Write for Sha256Writer<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Digest::update(self.0, buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Computes Bitcoin's double-SHA256 hash and returns the digest bytes as a little-endian hash.
#[must_use]
pub fn double_sha256(bytes: &[u8]) -> Hash256 {
    let first = Sha256::new().chain_update(bytes).finalize();
    let second = Sha256::new().chain_update(first).finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&second);
    Hash256::from_le_bytes(&out)
}

/// Finishes a streamed double-SHA256 over everything written to the engine.
pub(crate) fn finalize_double_sha256(engine: Sha256) -> Hash256 {
    let first = engine.finalize();
    let second = Sha256::digest(first);
    let bytes: [u8; 32] = second.into();
    Hash256::from_le_bytes(&bytes)
}

/// Errors returned while decoding consensus structures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer ends before the structure is complete.
    #[error(
        "unexpected end of consensus data: needed {needed} more byte(s), {available} available"
    )]
    EndOfData {
        /// Additional bytes required.
        needed: usize,
        /// Bytes actually available.
        available: usize,
    },
    /// A compact-size varint was truncated or non-canonical.
    #[error("invalid compact-size varint: {0}")]
    Varint(#[from] varint::VarintError),
    /// The segwit marker was followed by a flag byte other than 0x01 (BIP144).
    #[error("invalid segwit marker flag byte: expected 0x01, got {got:#04x}")]
    InvalidSegwitFlag {
        /// The rejected flag byte.
        got: u8,
    },
    /// The BIP144 marker/flag was used but every witness stack is empty, so the
    /// encoding could not round-trip (the encoder emits no marker/flag without
    /// witness data).
    #[error("superfluous segwit encoding: witness flag set but no witnesses present")]
    SuperfluousWitness,
    /// A decoded value did not consume the entire input buffer.
    #[error("{remaining} trailing byte(s) after decoded value")]
    TrailingBytes {
        /// Number of bytes left over.
        remaining: usize,
    },
}

/// Bitcoin consensus encoding for native protocol types.
pub trait ConsensusEncode {
    /// Writes the consensus serialization of `self` to the writer.
    fn consensus_encode(&self, writer: &mut impl Write) -> io::Result<()>;
}

/// Bitcoin consensus decoding for native protocol types.
pub trait ConsensusDecode: Sized {
    /// Reads the consensus serialization of `Self`, consuming exactly the value's bytes.
    fn consensus_decode(reader: &mut &[u8]) -> Result<Self, DecodeError>;
}

/// Serializes a consensus-encodable value into a byte vector.
#[must_use]
pub fn consensus_bytes<T: ConsensusEncode + ?Sized>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Err(error) = value.consensus_encode(&mut bytes) {
        panic!("consensus encoding into Vec failed: {error}");
    }
    bytes
}

/// Consensus serialization length without allocating the encoded bytes.
#[must_use]
pub fn consensus_len<T: ConsensusEncode + ?Sized>(value: &T) -> usize {
    let mut total = 0_usize;
    if let Err(error) = value.consensus_encode(&mut CountWriter(&mut total)) {
        panic!("consensus encoding into count writer failed: {error}");
    }
    total
}

/// Decodes a complete value from `bytes`, rejecting any trailing bytes.
pub fn deserialize<T: ConsensusDecode>(bytes: &[u8]) -> Result<T, DecodeError> {
    let mut reader = bytes;
    let value = T::consensus_decode(&mut reader)?;
    let remaining = reader.len();
    if remaining != 0 {
        return Err(DecodeError::TrailingBytes { remaining });
    }
    Ok(value)
}

pub(crate) fn take<'a>(reader: &mut &'a [u8], needed: usize) -> Result<&'a [u8], DecodeError> {
    if reader.len() < needed {
        return Err(DecodeError::EndOfData {
            needed,
            available: reader.len(),
        });
    }
    let (head, tail) = reader.split_at(needed);
    *reader = tail;
    Ok(head)
}

pub(crate) fn read_u8(reader: &mut &[u8]) -> Result<u8, DecodeError> {
    Ok(take(reader, 1)?[0])
}

pub(crate) fn read_array<const N: usize>(reader: &mut &[u8]) -> Result<[u8; N], DecodeError> {
    let mut out = [0_u8; N];
    out.copy_from_slice(take(reader, N)?);
    Ok(out)
}

pub(crate) fn read_u32_le(reader: &mut &[u8]) -> Result<u32, DecodeError> {
    Ok(u32::from_le_bytes(read_array::<4>(reader)?))
}

pub(crate) fn read_i32_le(reader: &mut &[u8]) -> Result<i32, DecodeError> {
    Ok(i32::from_le_bytes(read_array::<4>(reader)?))
}

pub(crate) fn read_u64_le(reader: &mut &[u8]) -> Result<u64, DecodeError> {
    Ok(u64::from_le_bytes(read_array::<8>(reader)?))
}

pub(crate) fn read_compact(reader: &mut &[u8]) -> Result<u64, DecodeError> {
    let (value, consumed) = varint::decode(reader)?;
    *reader = &reader[consumed..];
    Ok(value)
}

pub(crate) fn read_script(reader: &mut &[u8]) -> Result<Vec<u8>, DecodeError> {
    let len = read_compact(reader)?;
    let needed = usize::try_from(len).unwrap_or(usize::MAX);
    Ok(take(reader, needed)?.to_vec())
}

pub(crate) fn write_compact(writer: &mut impl Write, value: u64) -> io::Result<()> {
    writer.write_all(varint::encode(value).as_slice())
}

/// Compact-size length of a `Vec` slice: a `Vec` is always shorter than
/// `usize::MAX`, so the conversion cannot fail.
pub(crate) fn compact_len(len: usize) -> u64 {
    u64::try_from(len).unwrap_or_else(|_| unreachable!("vec length fits u64"))
}

pub(crate) fn write_script(writer: &mut impl Write, script: &[u8]) -> io::Result<()> {
    write_compact(writer, compact_len(script.len()))?;
    writer.write_all(script)
}

impl ConsensusEncode for OutPoint {
    fn consensus_encode(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(self.txid.as_bytes())?;
        writer.write_all(&self.vout.to_le_bytes())
    }
}

impl ConsensusDecode for OutPoint {
    fn consensus_decode(reader: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            txid: Txid(Hash256::from_le_bytes(&read_array::<32>(reader)?)),
            vout: read_u32_le(reader)?,
        })
    }
}

impl ConsensusEncode for Header {
    fn consensus_encode(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&self.version.to_le_bytes())?;
        writer.write_all(self.prev_blockhash.as_bytes())?;
        writer.write_all(self.merkle_root.as_byte_array())?;
        writer.write_all(&self.time.to_le_bytes())?;
        writer.write_all(&self.bits.to_le_bytes())?;
        writer.write_all(&self.nonce.to_le_bytes())
    }
}

impl ConsensusDecode for Header {
    fn consensus_decode(reader: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            version: read_i32_le(reader)?,
            prev_blockhash: BlockHash(Hash256::from_le_bytes(&read_array::<32>(reader)?)),
            merkle_root: Hash256::from_le_bytes(&read_array::<32>(reader)?),
            time: read_u32_le(reader)?,
            bits: read_u32_le(reader)?,
            nonce: read_u32_le(reader)?,
        })
    }
}

impl ConsensusEncode for TxOut {
    fn consensus_encode(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&self.value.to_le_bytes())?;
        write_script(writer, &self.script_pubkey)
    }
}

impl ConsensusDecode for TxOut {
    fn consensus_decode(reader: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            value: read_u64_le(reader)?,
            script_pubkey: read_script(reader)?,
        })
    }
}

impl ConsensusEncode for TxIn {
    fn consensus_encode(&self, writer: &mut impl Write) -> io::Result<()> {
        self.previous_output.consensus_encode(writer)?;
        write_script(writer, &self.script_sig)?;
        writer.write_all(&self.sequence.to_le_bytes())
    }
}

impl ConsensusDecode for TxIn {
    fn consensus_decode(reader: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            previous_output: OutPoint::consensus_decode(reader)?,
            script_sig: read_script(reader)?,
            sequence: read_u32_le(reader)?,
            witness: Vec::new(),
        })
    }
}

/// Serializes a transaction; `with_witness` controls the BIP144 marker/flag and witness
/// sections (emitted only when some input carries witness data).
pub(crate) fn encode_tx(tx: &Tx, writer: &mut impl Write, with_witness: bool) -> io::Result<()> {
    writer.write_all(&tx.version.to_le_bytes())?;
    let has_witness = with_witness && tx.inputs.iter().any(|input| !input.witness.is_empty());
    if has_witness {
        writer.write_all(&[0x00, 0x01])?;
    }
    write_compact(writer, compact_len(tx.inputs.len()))?;
    for input in &tx.inputs {
        input.consensus_encode(writer)?;
    }
    write_compact(writer, compact_len(tx.outputs.len()))?;
    for output in &tx.outputs {
        output.consensus_encode(writer)?;
    }
    if has_witness {
        for input in &tx.inputs {
            write_compact(writer, compact_len(input.witness.len()))?;
            for item in &input.witness {
                write_compact(writer, compact_len(item.len()))?;
                writer.write_all(item)?;
            }
        }
    }
    writer.write_all(&tx.lock_time.to_le_bytes())
}

/// Decodes a transaction, accepting the BIP144 marker/flag/witness layout.
pub(crate) fn decode_tx(reader: &mut &[u8]) -> Result<Tx, DecodeError> {
    let version = read_i32_le(reader)?;
    let mut input_count = read_compact(reader)?;
    let mut segwit = false;
    if input_count == 0 {
        // BIP144: a zero input count is the segwit marker; the flag byte must be 0x01.
        let flag = read_u8(reader)?;
        if flag != 0x01 {
            return Err(DecodeError::InvalidSegwitFlag { got: flag });
        }
        segwit = true;
        input_count = read_compact(reader)?;
    }

    let mut inputs = Vec::new();
    for _ in 0..input_count {
        inputs.push(TxIn::consensus_decode(reader)?);
    }
    let mut outputs = Vec::new();
    let output_count = read_compact(reader)?;
    for _ in 0..output_count {
        outputs.push(TxOut::consensus_decode(reader)?);
    }
    if segwit {
        for input in &mut inputs {
            let item_count = read_compact(reader)?;
            let mut witness = Vec::new();
            for _ in 0..item_count {
                let len = read_compact(reader)?;
                let needed = usize::try_from(len).unwrap_or(usize::MAX);
                witness.push(take(reader, needed)?.to_vec());
            }
            input.witness = witness;
        }
        // BIP144: the marker/flag exists only to carry witness data. Core rejects the
        // all-empty form ("Superfluous witness record") and rust-bitcoin rejects the
        // non-empty-input form ("witness flag set but no witnesses present"); we reject
        // every such encoding here, before the lock time, matching the check position
        // of both oracles, so every accepted encoding re-encodes byte-identically.
        if !inputs.iter().any(|input| !input.witness.is_empty()) {
            return Err(DecodeError::SuperfluousWitness);
        }
    }
    let lock_time = read_u32_le(reader)?;

    Ok(Tx {
        version,
        inputs,
        outputs,
        lock_time,
    })
}

impl ConsensusEncode for Tx {
    fn consensus_encode(&self, writer: &mut impl Write) -> io::Result<()> {
        encode_tx(self, writer, true)
    }
}

impl ConsensusDecode for Tx {
    fn consensus_decode(reader: &mut &[u8]) -> Result<Self, DecodeError> {
        decode_tx(reader)
    }
}

impl ConsensusEncode for Block {
    fn consensus_encode(&self, writer: &mut impl Write) -> io::Result<()> {
        self.header.consensus_encode(writer)?;
        write_compact(writer, compact_len(self.txs.len()))?;
        for tx in &self.txs {
            tx.consensus_encode(writer)?;
        }
        Ok(())
    }
}

impl ConsensusDecode for Block {
    fn consensus_decode(reader: &mut &[u8]) -> Result<Self, DecodeError> {
        let header = <Header as ConsensusDecode>::consensus_decode(reader)?;
        let tx_count = read_compact(reader)?;
        let mut txs = Vec::new();
        for _ in 0..tx_count {
            txs.push(<Tx as ConsensusDecode>::consensus_decode(reader)?);
        }
        Ok(Self { header, txs })
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions")]
    use super::{DecodeError, deserialize, varint};

    type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

    fn sample_header_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1_i32.to_le_bytes());
        bytes.extend_from_slice(&[0x11_u8; 32]);
        bytes.extend_from_slice(&[0x22_u8; 32]);
        bytes.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
        bytes.extend_from_slice(&0x207f_ffff_u32.to_le_bytes());
        bytes.extend_from_slice(&0x1234_5678_u32.to_le_bytes());
        bytes
    }

    #[test]
    fn header_roundtrips_through_consensus_bytes() -> Result<()> {
        let bytes = sample_header_bytes();
        let header = crate::Header::consensus_decode(&bytes[..])?;
        assert_eq!(header.version, 1);
        assert_eq!(header.prev_blockhash.as_bytes(), &[0x11_u8; 32]);
        assert_eq!(header.merkle_root.as_byte_array(), &[0x22_u8; 32]);
        assert_eq!(crate::encode::consensus_bytes(&header), bytes);
        Ok(())
    }

    #[test]
    fn truncated_header_reports_end_of_data() {
        let bytes = sample_header_bytes();
        for len in 0..bytes.len() {
            let error = crate::Header::consensus_decode(&bytes[..len])
                .expect_err("truncated header must fail");
            assert!(matches!(
                error,
                DecodeError::EndOfData { .. } | DecodeError::Varint(_)
            ));
        }
    }

    #[test]
    fn non_canonical_varint_input_count_is_rejected() {
        // version || non-canonical 0xfd prefix || count 0x0001
        let mut bytes = 1_i32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0xfd, 0x01, 0x00]);
        let error =
            crate::Tx::consensus_decode(&bytes).expect_err("non-canonical varint must fail");
        assert!(matches!(
            error,
            DecodeError::Varint(varint::VarintError::NonCanonical { .. })
        ));
    }

    #[test]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the `?`-chained body reads clearest as a Result-returning test even though the harness ignores it"
    )]
    fn trailing_bytes_are_rejected_by_deserialize() -> Result<()> {
        use crate::{OutPoint, Tx, TxIn, Txid};

        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: Vec::new(),
            lock_time: 0,
        };
        let mut bytes = crate::encode::consensus_bytes(&tx);
        bytes.push(0xff);
        assert!(matches!(
            deserialize::<Tx>(&bytes),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        ));
        Ok(())
    }

    #[test]
    fn single_input_tx_without_witness_roundtrips_without_marker() -> Result<()> {
        use crate::{OutPoint, Tx, TxIn, Txid};

        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig: vec![0x51],
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            outputs: Vec::new(),
            lock_time: 7,
        };
        let bytes = crate::encode::consensus_bytes(&tx);
        // No witness data: no marker/flag is emitted.
        assert_eq!(&bytes[4], &0x01);
        assert_eq!(deserialize::<Tx>(&bytes)?, tx);
        Ok(())
    }
    #[test]
    fn superfluous_segwit_marker_is_rejected() -> Result<()> {
        use crate::{OutPoint, Tx, TxIn, Txid};

        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig: vec![0x51],
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            outputs: Vec::new(),
            lock_time: 7,
        };
        let stripped = crate::encode::consensus_bytes(&tx);
        assert_eq!(&stripped[4], &0x01, "witness-free tx carries no marker");

        // Splice the BIP144 marker/flag after the version bytes and append an
        // all-empty witness section (a zero item-count per input) before the lock time.
        let (prefix, lock_time) = stripped.split_at(stripped.len() - 4);
        let mut marked = prefix.to_vec();
        marked.splice(4..4, [0x00_u8, 0x01]);
        marked.extend(std::iter::repeat_n(0x00_u8, tx.inputs.len()));
        marked.extend_from_slice(lock_time);

        // Marker+flag with an all-empty witness section: Core rejects this as a
        // superfluous witness record, and so do we. rust-bitcoin 0.32 also rejects
        // the non-empty-input form; that crate is not an oracle for this crate.
        assert_eq!(
            deserialize::<Tx>(&marked),
            Err(DecodeError::SuperfluousWitness)
        );

        // The witness-stripped encoding of the same tx is accepted and round-trips.
        assert_eq!(deserialize::<Tx>(&stripped)?, tx);
        assert_eq!(crate::encode::consensus_bytes(&tx), stripped);

        // Degenerate zero-input marker+flag encoding: Core rejects it ("Superfluous
        // witness record") and so do we, since the encoder could never reproduce the
        // marker/flag on re-encode. rust-bitcoin 0.32 accepts this shape (`!input
        // .is_empty()` guard); that divergence is deliberate and not inherited.
        let mut zero_input = 2_i32.to_le_bytes().to_vec();
        zero_input.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            deserialize::<Tx>(&zero_input),
            Err(DecodeError::SuperfluousWitness)
        );
        Ok(())
    }
}
