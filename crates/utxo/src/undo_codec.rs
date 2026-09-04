//! Versioned on-disk encoding for [`UndoBatch`].
//!
//! An undo record is what lets the node disconnect a block during a chain
//! reorganization. Two properties matter more than compactness:
//!
//! 1. **Versioned.** The first byte is a format version, so a record written by
//!    an older binary is rejected rather than misread.
//! 2. **Bound to its block.** The record carries the hash of the block it
//!    undoes, and [`decode`] refuses a record whose hash does not match the
//!    block being disconnected. Keying by height alone would let a stale record
//!    from an abandoned branch be replayed against a different block at the
//!    same height, which silently corrupts the UTXO set.
//!
//! Output payloads use the native `bitcoin_rs_primitives` consensus encoding
//! rather than a hand-rolled layout, so the format cannot drift from the
//! encoding the rest of the node already agrees on.

use std::collections::HashSet;

use bitcoin_rs_primitives::{ConsensusDecode, ConsensusEncode, Hash256, OutPoint, TxOut};
use thiserror::Error;

use crate::set::{UndoBatch, UtxoAdd};

/// Current undo-record format version.
pub const UNDO_FORMAT_VERSION: u8 = 1;

#[cfg(test)]
const VERSION_BYTES: usize = 1;
#[cfg(test)]
const BLOCK_HASH_BYTES: usize = 32;
#[cfg(test)]
const COUNT_BYTES: usize = core::mem::size_of::<u32>();
#[cfg(test)]
const RESTORE_COUNT_OFFSET: usize = VERSION_BYTES + BLOCK_HASH_BYTES;
#[cfg(test)]
const RESTORE_TRAILER_BYTES: usize = 1 + core::mem::size_of::<u32>() + COUNT_BYTES;

/// Errors returned when decoding an undo record.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum UndoCodecError {
    /// The record ended before a field was fully read.
    #[error("undo record truncated: wanted {wanted} more bytes, {available} available")]
    Truncated {
        /// Bytes the field required.
        wanted: usize,
        /// Bytes actually remaining.
        available: usize,
    },
    /// The record was written by an incompatible format version.
    #[error("unsupported undo record version {found}, expected {expected}")]
    UnsupportedVersion {
        /// Version byte read from the record.
        found: u8,
        /// Version this binary writes.
        expected: u8,
    },
    /// The record belongs to a different block than the one being disconnected.
    #[error("undo record is for block {found}, not {expected}")]
    BlockHashMismatch {
        /// Hash carried by the record.
        found: Hash256,
        /// Hash of the block being disconnected.
        expected: Hash256,
    },
    /// An output payload was not valid consensus encoding.
    #[error("undo record contains a malformed transaction output")]
    MalformedTxOut,
    /// Bytes remained after the final field.
    #[error("undo record has {trailing} trailing bytes")]
    TrailingBytes {
        /// Count of unconsumed bytes.
        trailing: usize,
    },
    /// A count field claims more entries than the remaining bytes can hold.
    #[error("undo record claims {count} entries but only {available} bytes remain")]
    CountTooLarge {
        /// Entry count read from the record.
        count: u32,
        /// Bytes remaining when the count was read.
        available: usize,
    },
    /// The coinbase flag was neither 0 nor 1.
    #[error("undo record coinbase flag {found} is not 0 or 1")]
    InvalidCoinbase {
        /// Byte read from the record.
        found: u8,
    },
    /// The same outpoint appears twice, which a well-formed record never does.
    #[error("undo record repeats outpoint {txid}:{vout}")]
    DuplicateOutpoint {
        /// Repeated transaction id.
        txid: Hash256,
        /// Repeated output index.
        vout: u32,
    },
}

/// Encodes `batch` as a record bound to `block_hash`.
#[must_use]
pub fn encode(batch: &UndoBatch, block_hash: Hash256) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(UNDO_FORMAT_VERSION);
    out.extend_from_slice(&block_hash.to_le_bytes());

    let restores = batch.restores();
    out.extend_from_slice(&u32_len(restores.len()).to_le_bytes());
    for add in restores {
        put_outpoint(&mut out, add.outpoint);
        add.txout.consensus_encode(&mut out);
        out.push(u8::from(add.coinbase));
        out.extend_from_slice(&add.height.to_le_bytes());
    }

    let removes = batch.removes();
    out.extend_from_slice(&u32_len(removes.len()).to_le_bytes());
    for outpoint in removes {
        put_outpoint(&mut out, *outpoint);
    }
    out
}

/// Decodes a record, rejecting any that is not for `expected_hash`.
pub fn decode(bytes: &[u8], expected_hash: Hash256) -> Result<UndoBatch, UndoCodecError> {
    // A restore is at least an outpoint, a minimal TxOut, a flag, and a height.
    const MIN_RESTORE_BYTES: usize = 36 + 9 + 1 + 4;
    const MIN_REMOVE_BYTES: usize = 36;

    let mut cursor = Cursor::new(bytes);

    let version = cursor.take_array::<1>()?[0];
    if version != UNDO_FORMAT_VERSION {
        return Err(UndoCodecError::UnsupportedVersion {
            found: version,
            expected: UNDO_FORMAT_VERSION,
        });
    }

    let found = Hash256::from_le_bytes(&cursor.take_array::<32>()?);
    if found != expected_hash {
        return Err(UndoCodecError::BlockHashMismatch {
            found,
            expected: expected_hash,
        });
    }

    let restore_count = cursor.take_count(MIN_RESTORE_BYTES)?;
    let mut restores = Vec::with_capacity(bounded_capacity(restore_count));
    let mut seen = HashSet::with_capacity(bounded_capacity(restore_count));
    for _ in 0..restore_count {
        let outpoint = cursor.take_outpoint()?;
        reject_duplicate(&mut seen, outpoint)?;
        let txout = cursor.take_txout()?;
        let coinbase = match cursor.take_array::<1>()?[0] {
            0 => false,
            1 => true,
            found => return Err(UndoCodecError::InvalidCoinbase { found }),
        };
        let height = cursor.take_u32()?;
        restores.push(UtxoAdd::new(outpoint, txout, coinbase, height));
    }

    let remove_count = cursor.take_count(MIN_REMOVE_BYTES)?;
    let mut removes = Vec::with_capacity(bounded_capacity(remove_count));
    // `seen` deliberately carries over: a block cannot both restore and remove
    // the same outpoint, so an appearance in both halves is corruption too.
    for _ in 0..remove_count {
        let outpoint = cursor.take_outpoint()?;
        reject_duplicate(&mut seen, outpoint)?;
        removes.push(outpoint);
    }

    let trailing = cursor.remaining();
    if trailing != 0 {
        return Err(UndoCodecError::TrailingBytes { trailing });
    }
    Ok(UndoBatch::from_parts(restores, removes))
}

/// Caps the pre-allocation a count field can request.
///
/// The count is read from bytes on disk, so a corrupt record must not be able
/// to ask for an unbounded allocation before its contents are validated.
fn bounded_capacity(count: u32) -> usize {
    const MAX_PREALLOC: u32 = 4096;
    usize::try_from(count.min(MAX_PREALLOC)).unwrap_or(0)
}

/// Converts an entry count for the wire.
///
/// Saturation is unreachable: a block is capped at 4 000 000 weight units, so it
/// cannot carry anywhere near `u32::MAX` outputs or inputs.
fn u32_len(len: usize) -> u32 {
    debug_assert!(u32::try_from(len).is_ok(), "undo entry count exceeds u32");
    u32::try_from(len).unwrap_or(u32::MAX)
}

fn reject_duplicate(
    seen: &mut HashSet<OutPoint>,
    outpoint: OutPoint,
) -> Result<(), UndoCodecError> {
    if seen.insert(outpoint) {
        return Ok(());
    }
    Err(UndoCodecError::DuplicateOutpoint {
        txid: outpoint.txid.into(),
        vout: outpoint.vout,
    })
}

fn put_outpoint(out: &mut Vec<u8>, outpoint: OutPoint) {
    out.extend_from_slice(outpoint.txid.as_bytes());
    out.extend_from_slice(&outpoint.vout.to_le_bytes());
}

/// Bounds-checked forward reader over the record.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, wanted: usize) -> Result<&'a [u8], UndoCodecError> {
        let available = self.remaining();
        if available < wanted {
            return Err(UndoCodecError::Truncated { wanted, available });
        }
        let end = self.offset.saturating_add(wanted);
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(UndoCodecError::Truncated { wanted, available })?;
        self.offset = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], UndoCodecError> {
        let slice = self.take(N)?;
        <[u8; N]>::try_from(slice).map_err(|_| UndoCodecError::Truncated {
            wanted: N,
            available: slice.len(),
        })
    }

    fn take_u32(&mut self) -> Result<u32, UndoCodecError> {
        Ok(u32::from_le_bytes(self.take_array::<4>()?))
    }

    /// Reads an entry count and rejects one the remaining bytes cannot hold.
    ///
    /// Without this a corrupt count sends the caller round a loop that can only
    /// end in a truncation error, and reports the wrong cause.
    fn take_count(&mut self, min_entry_bytes: usize) -> Result<u32, UndoCodecError> {
        let count = self.take_u32()?;
        let available = self.remaining();
        let needed = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(min_entry_bytes));
        match needed {
            Some(needed) if needed <= available => Ok(count),
            _ => Err(UndoCodecError::CountTooLarge { count, available }),
        }
    }

    fn take_outpoint(&mut self) -> Result<OutPoint, UndoCodecError> {
        let txid = Hash256::from_le_bytes(&self.take_array::<32>()?);
        let vout = self.take_u32()?;
        Ok(OutPoint::new(txid.into(), vout))
    }

    fn take_txout(&mut self) -> Result<TxOut, UndoCodecError> {
        let rest = self
            .bytes
            .get(self.offset..)
            .ok_or(UndoCodecError::MalformedTxOut)?;
        let mut reader = rest;
        let before = reader.len();
        let txout =
            TxOut::consensus_decode(&mut reader).map_err(|_| UndoCodecError::MalformedTxOut)?;
        let consumed = before.saturating_sub(reader.len());
        self.offset = self.offset.saturating_add(consumed);
        Ok(txout)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COUNT_BYTES, RESTORE_COUNT_OFFSET, RESTORE_TRAILER_BYTES, UNDO_FORMAT_VERSION,
        UndoCodecError, UtxoAdd, decode, encode,
    };
    use crate::set::UndoBatch;
    use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};

    pub(super) fn hash(byte: u8) -> Hash256 {
        Hash256::from_le_bytes(&[byte; 32])
    }

    pub(super) fn txout(sats: u64) -> TxOut {
        TxOut {
            value: sats,
            script_pubkey: vec![0x51, byte_of(sats)],
        }
    }

    fn byte_of(sats: u64) -> u8 {
        u8::try_from(sats % 251).unwrap_or(0)
    }

    fn sample() -> UndoBatch {
        let mut batch = UndoBatch::default();
        batch.restore(UtxoAdd::new(
            OutPoint::new(hash(1).into(), 0),
            txout(50_000),
            true,
            11,
        ));
        batch.restore(UtxoAdd::new(
            OutPoint::new(hash(2).into(), 7),
            txout(1),
            false,
            12,
        ));
        batch.remove(OutPoint::new(hash(3).into(), 0));
        batch.remove(OutPoint::new(hash(3).into(), 1));
        batch
    }

    #[test]
    fn round_trip_preserves_every_field() -> Result<(), UndoCodecError> {
        let batch = sample();
        let decoded = decode(&encode(&batch, hash(9)), hash(9))?;

        assert_eq!(decoded.restores().len(), batch.restores().len());
        for (out, expected) in decoded.restores().iter().zip(batch.restores()) {
            assert_eq!(out.outpoint, expected.outpoint);
            assert_eq!(out.txout, expected.txout);
            assert_eq!(out.coinbase, expected.coinbase);
            assert_eq!(out.height, expected.height);
        }
        assert_eq!(decoded.removes(), batch.removes());
        Ok(())
    }

    #[test]
    fn an_empty_batch_round_trips() -> Result<(), UndoCodecError> {
        let decoded = decode(&encode(&UndoBatch::default(), hash(4)), hash(4))?;
        assert!(decoded.is_empty());
        Ok(())
    }

    #[test]
    fn a_record_for_another_block_is_refused() {
        // The trap this check exists for: a stale record from an abandoned
        // branch must never be replayed against a different block.
        let bytes = encode(&sample(), hash(1));
        assert!(matches!(
            decode(&bytes, hash(2)),
            Err(UndoCodecError::BlockHashMismatch { .. })
        ));
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let mut bytes = encode(&sample(), hash(1));
        bytes[0] = UNDO_FORMAT_VERSION.wrapping_add(1);
        assert!(matches!(
            decode(&bytes, hash(1)),
            Err(UndoCodecError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn a_truncated_record_is_refused() {
        let bytes = encode(&sample(), hash(1));
        for cut in [1_usize, 8, 20, bytes.len() - 1] {
            assert!(
                decode(&bytes[..cut], hash(1)).is_err(),
                "truncation at {cut} must be refused"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = encode(&sample(), hash(1));
        bytes.push(0);
        assert!(matches!(
            decode(&bytes, hash(1)),
            Err(UndoCodecError::TrailingBytes { trailing: 1 })
        ));
    }

    #[test]
    fn an_impossible_entry_count_is_refused_without_looping() {
        let mut bytes = encode(&UndoBatch::default(), hash(1));
        // Overwrite the restore count with a value no record could hold.
        let count = RESTORE_COUNT_OFFSET..RESTORE_COUNT_OFFSET + COUNT_BYTES;
        bytes[count].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decode(&bytes, hash(1)),
            Err(UndoCodecError::CountTooLarge { .. })
        ));
    }

    #[test]
    fn a_non_canonical_coinbase_flag_is_refused() {
        let mut batch = UndoBatch::default();
        batch.restore(UtxoAdd::new(
            OutPoint::new(hash(1).into(), 0),
            txout(10),
            false,
            5,
        ));
        let mut bytes = encode(&batch, hash(1));
        let flag = bytes.len() - RESTORE_TRAILER_BYTES;
        bytes[flag] = 2;
        assert!(matches!(
            decode(&bytes, hash(1)),
            Err(UndoCodecError::InvalidCoinbase { found: 2 })
        ));
    }

    #[test]
    fn a_repeated_outpoint_is_refused() {
        let mut batch = UndoBatch::default();
        batch.remove(OutPoint::new(hash(5).into(), 0));
        batch.remove(OutPoint::new(hash(5).into(), 0));
        assert!(matches!(
            decode(&encode(&batch, hash(1)), hash(1)),
            Err(UndoCodecError::DuplicateOutpoint { .. })
        ));
    }
}

#[cfg(test)]
mod cross_half_tests {
    use super::tests::{hash, txout};
    use super::{UndoCodecError, UtxoAdd, decode, encode};
    use crate::set::UndoBatch;
    use bitcoin_rs_primitives::OutPoint;

    /// A block cannot both spend and create the same outpoint: the apply path
    /// filters same-block spends out of both halves. An outpoint appearing in
    /// both is therefore a corrupt record, not a legal one.
    #[test]
    fn an_outpoint_in_both_halves_is_refused() {
        let shared = OutPoint::new(hash(6).into(), 3);
        let mut batch = UndoBatch::default();
        batch.restore(UtxoAdd::new(shared, txout(10), false, 4));
        batch.remove(shared);
        assert!(matches!(
            decode(&encode(&batch, hash(1)), hash(1)),
            Err(UndoCodecError::DuplicateOutpoint { .. })
        ));
    }
}
