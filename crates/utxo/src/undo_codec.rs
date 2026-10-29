//! Versioned on-disk encoding for [`UndoBatch`].
//! 1. **Versioned.** The first byte is a format version, so a record written by
//!    an older binary is rejected rather than misread.

use std::collections::HashSet;

use bitcoin_rs_primitives::{ConsensusDecode, ConsensusEncode, Hash256, OutPoint, TxOut};
use thiserror::Error;

use crate::contract::{UndoBatch, UtxoAdd};

pub(crate) const UNDO_FORMAT_VERSION: u8 = 1;

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

/// Maximum encoded record for a consensus-valid block.
pub fn record_size_limit(block: &bitcoin_rs_primitives::Block, max_spent_script: usize) -> usize {
    let inputs = block
        .txs
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .map(|tx| tx.inputs.len())
        .sum::<usize>();
    let outputs = block.txs.iter().map(|tx| tx.outputs.len()).sum::<usize>();
    41_usize
        .saturating_add(inputs.saturating_mul(52_usize.saturating_add(max_spent_script)))
        .saturating_add(outputs.saturating_mul(52 + 36))
        .saturating_add(block.total_size())
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum UndoCodecError {
    #[error("undo record truncated: wanted {wanted} more bytes, {available} available")]
    Truncated { wanted: usize, available: usize },
    #[error("unsupported undo record version {found}, expected {expected}")]
    UnsupportedVersion { found: u8, expected: u8 },
    #[error("undo record is for block {found}, not {expected}")]
    BlockHashMismatch { found: Hash256, expected: Hash256 },
    #[error("undo record contains a malformed transaction output")]
    MalformedTxOut,
    #[error("undo record has {trailing} trailing bytes")]
    TrailingBytes { trailing: usize },
    #[error("undo record claims {count} entries but only {available} bytes remain")]
    CountTooLarge { count: u32, available: usize },
    #[error("undo record claims {count} entries, exceeding the block-derived limit {limit}")]
    BlockCountLimit { count: u32, limit: usize },
    #[error("undo record coinbase flag {found} is not 0 or 1")]
    InvalidCoinbase { found: u8 },
    #[error("undo record repeats outpoint {txid}:{vout}")]
    DuplicateOutpoint { txid: Hash256, vout: u32 },
}

#[must_use]
pub(crate) fn encode(batch: &UndoBatch, block_hash: Hash256) -> Vec<u8> {
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
    decode_bounded(bytes, expected_hash, usize::MAX, usize::MAX)
}

pub(crate) fn decode_bounded(
    bytes: &[u8],
    expected_hash: Hash256,
    max_restores: usize,
    max_removes: usize,
) -> Result<UndoBatch, UndoCodecError> {
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
    if usize::try_from(restore_count).unwrap_or(usize::MAX) > max_restores {
        return Err(UndoCodecError::BlockCountLimit {
            count: restore_count,
            limit: max_restores,
        });
    }
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
    if usize::try_from(remove_count).unwrap_or(usize::MAX) > max_removes {
        return Err(UndoCodecError::BlockCountLimit {
            count: remove_count,
            limit: max_removes,
        });
    }
    let mut removes = Vec::with_capacity(bounded_capacity(remove_count));
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

fn bounded_capacity(count: u32) -> usize {
    const MAX_PREALLOC: u32 = 4096;
    usize::try_from(count.min(MAX_PREALLOC)).unwrap_or(0)
}

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
    use crate::contract::UndoBatch;
    use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, TxOut};

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_le_bytes(&[byte; 32])
    }

    fn outpoint(txid: u8, vout: u32) -> OutPoint {
        OutPoint::new(hash(txid).into(), vout)
    }

    fn restore(batch: &mut UndoBatch, op: OutPoint, sats: u64, coinbase: bool, height: u32) {
        let txout = TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: vec![0x51, u8::try_from(sats % 251).unwrap_or(0)].into(),
        };
        batch.restore(UtxoAdd::new(op, txout, coinbase, height));
    }

    fn sample() -> UndoBatch {
        let mut batch = UndoBatch::empty();
        restore(&mut batch, outpoint(1, 0), 50_000, true, 11);
        restore(&mut batch, outpoint(2, 7), 1, false, 12);
        batch.remove(outpoint(3, 0));
        batch.remove(outpoint(3, 1));
        batch
    }

    #[test]
    fn read_bound_covers_spent_scripts_and_bip30_overwrite_bytes() {
        let mut block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        block.txs[0].outputs[0].script_pubkey = vec![0x51; 20_000].into();
        let mut spend = block.txs[0].clone();
        spend.inputs[0].previous_output = outpoint(1, 0);
        spend.outputs[0].script_pubkey = vec![0x51].into();
        let mut batch = UndoBatch::empty();
        batch.restore(UtxoAdd::new(
            outpoint(1, 0),
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: vec![0x51; 10_000].into(),
            },
            false,
            1,
        ));
        batch.restore(UtxoAdd::new(
            OutPoint::new(block.txs[0].txid(), 0),
            block.txs[0].outputs[0].clone(),
            true,
            1,
        ));
        batch.remove(OutPoint::new(spend.txid(), 0));
        block.txs.push(spend);
        let actual = encode(&batch, block.block_hash().into()).len();
        assert!(
            actual > super::record_size_limit(&block, 0),
            "spent scripts are not bounded by current output bytes"
        );
        assert!(
            actual <= super::record_size_limit(&block, 10_000),
            "both restore sources fit the codec bound"
        );
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
        let decoded = decode(&encode(&UndoBatch::empty(), hash(4)), hash(4))?;
        assert!(decoded.restores().is_empty() && decoded.removes().is_empty());
        Ok(())
    }

    #[test]
    fn a_corrupt_record_is_refused_with_the_matching_error() {
        fn corrupt(mutate: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
            let mut bytes = encode(&sample(), hash(1));
            mutate(&mut bytes);
            bytes
        }
        fn single_restore_with_coinbase_byte(byte: u8) -> Vec<u8> {
            let mut batch = UndoBatch::empty();
            restore(&mut batch, outpoint(1, 0), 10, false, 5);
            let mut bytes = encode(&batch, hash(1));
            let flag = bytes.len() - RESTORE_TRAILER_BYTES;
            bytes[flag] = byte;
            bytes
        }
        fn twice(outpoint: OutPoint, in_both_halves: bool) -> Vec<u8> {
            let mut batch = UndoBatch::empty();
            if in_both_halves {
                restore(&mut batch, outpoint, 10, false, 4);
            } else {
                batch.remove(outpoint);
            }
            batch.remove(outpoint);
            encode(&batch, hash(1))
        }

        type Expected = fn(&UndoCodecError) -> bool;
        let cases: [(&str, Vec<u8>, Hash256, Expected); 7] = [
            (
                "another block",
                encode(&sample(), hash(1)),
                hash(2),
                |error| matches!(error, UndoCodecError::BlockHashMismatch { .. }),
            ),
            (
                "unknown version",
                corrupt(|bytes| bytes[0] = UNDO_FORMAT_VERSION.wrapping_add(1)),
                hash(1),
                |error| matches!(error, UndoCodecError::UnsupportedVersion { .. }),
            ),
            (
                "trailing bytes",
                corrupt(|bytes| bytes.push(0)),
                hash(1),
                |error| matches!(error, UndoCodecError::TrailingBytes { trailing: 1 }),
            ),
            (
                "impossible entry count",
                corrupt(|bytes| {
                    let count = RESTORE_COUNT_OFFSET..RESTORE_COUNT_OFFSET + COUNT_BYTES;
                    bytes[count].copy_from_slice(&u32::MAX.to_le_bytes());
                }),
                hash(1),
                |error| matches!(error, UndoCodecError::CountTooLarge { .. }),
            ),
            (
                "non-canonical coinbase flag",
                single_restore_with_coinbase_byte(2),
                hash(1),
                |error| matches!(error, UndoCodecError::InvalidCoinbase { found: 2 }),
            ),
            (
                "repeated outpoint",
                twice(OutPoint::new(hash(5).into(), 0), false),
                hash(1),
                |error| matches!(error, UndoCodecError::DuplicateOutpoint { .. }),
            ),
            (
                "outpoint in both halves",
                twice(OutPoint::new(hash(6).into(), 3), true),
                hash(1),
                |error| matches!(error, UndoCodecError::DuplicateOutpoint { .. }),
            ),
        ];

        for (name, bytes, block, expected) in cases {
            let Err(error) = decode(&bytes, block) else {
                panic!("{name}: a corrupt record decoded");
            };
            assert!(expected(&error), "{name}: unexpected error {error}");
        }

        let whole = encode(&sample(), hash(1));
        for cut in [1_usize, 8, 20, whole.len() - 1] {
            assert!(
                decode(&whole[..cut], hash(1)).is_err(),
                "truncation at {cut} must be refused"
            );
        }
    }
}
