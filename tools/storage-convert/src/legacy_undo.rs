use std::collections::HashSet;

use bitcoin_rs_consensus::primitives::{ConsensusDecode, Hash256, OutPoint, TxOut};
use bitcoin_rs_storage::utxo::contract::{UndoBatch, UndoCodecError, UtxoAdd};

const LEGACY_UNDO_FORMAT_VERSION: u8 = 1;

pub(crate) fn decode_legacy_undo_record(
    bytes: &[u8],
    expected_hash: Hash256,
) -> Result<UndoBatch, UndoCodecError> {
    const MIN_RESTORE_BYTES: usize = 36 + 9 + 1 + 4;
    const MIN_REMOVE_BYTES: usize = 36;
    let mut cursor = Cursor::new(bytes);
    let version = cursor.take_array::<1>()?[0];
    if version != LEGACY_UNDO_FORMAT_VERSION {
        return Err(UndoCodecError::UnsupportedVersion {
            found: version,
            expected: LEGACY_UNDO_FORMAT_VERSION,
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
pub(crate) fn encode_legacy_undo_record(batch: &UndoBatch, block_hash: Hash256) -> Vec<u8> {
    use bitcoin_rs_consensus::primitives::ConsensusEncode;
    let mut out = Vec::new();
    out.push(LEGACY_UNDO_FORMAT_VERSION);
    out.extend_from_slice(&block_hash.to_le_bytes());
    let restores = batch.restores();
    let restore_len = u32::try_from(restores.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&restore_len.to_le_bytes());
    for add in restores {
        out.extend_from_slice(add.outpoint.txid.as_bytes());
        out.extend_from_slice(&add.outpoint.vout.to_le_bytes());
        add.txout.consensus_encode(&mut out);
        out.push(u8::from(add.coinbase));
        out.extend_from_slice(&add.height.to_le_bytes());
    }
    let removes = batch.removes();
    let remove_len = u32::try_from(removes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&remove_len.to_le_bytes());
    for outpoint in removes {
        out.extend_from_slice(outpoint.txid.as_bytes());
        out.extend_from_slice(&outpoint.vout.to_le_bytes());
    }
    out
}
