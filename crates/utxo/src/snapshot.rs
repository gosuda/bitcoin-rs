use std::io::{Read, Write};

use bitcoin_rs_primitives::{Hash256, varint};
use sha2::{Digest, Sha256};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    UtxoError, UtxoKey, UtxoSet, UtxoSetView,
    record::{OneUtxoOut, OwnedUtxoOut, bitmap_vout_bit},
    shard::ShardTable,
};

const SNAPSHOT_MAGIC: u32 = 0x55_54_58_4f;
const SNAPSHOT_WRITE_VERSION: u32 = 3;
const SNAPSHOT_LEGACY_VERSION: u32 = 2;
const MUHASH_TRAILER_LEN: usize = 384;

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct SnapshotHeader {
    magic: u32,
    version: u32,
    tip_hash: [u8; 32],
    height: u32,
    record_count: u64,
}

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct SnapshotRecordHeader {
    shard_idx: u8,
    key_prefix: [u8; 8],
    txid: [u8; 32],
    vout_bitmap: u64,
    vout_count: u8,
}

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct SnapshotRecordHeaderV3 {
    shard_idx: u8,
    key_prefix: [u8; 8],
    txid: [u8; 32],
    vout_count: u8,
}

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct SnapshotVoutHeader {
    vout: u32,
    value: u64,
    height: u32,
    coinbase: u8,
    script_len: u16,
}

/// Result of loading a UTXO snapshot.
pub struct SnapshotLoad {
    /// Rebuilt UTXO set.
    pub set: UtxoSet,
    /// Snapshot tip hash.
    pub tip_hash: Hash256,
    /// Snapshot chain height.
    pub height: u32,
    /// `MuHash3072` trailer bytes.
    pub muhash_trailer: [u8; MUHASH_TRAILER_LEN],
}

/// Streams a native bitcoin-rs UTXO snapshot to `writer`.
pub fn write_snapshot(
    set: &UtxoSet,
    tip_hash: &Hash256,
    height: u32,
    writer: &mut impl Write,
) -> Result<[u8; MUHASH_TRAILER_LEN], UtxoError> {
    set.with_stable_view(|view| {
        let record_count = u64::try_from(view.record_count())
            .map_err(|_| UtxoError::SnapshotRecordCountTooLarge { count: u64::MAX })?;
        let header = SnapshotHeader {
            magic: SNAPSHOT_MAGIC.to_le(),
            version: SNAPSHOT_WRITE_VERSION.to_le(),
            tip_hash: tip_hash.to_le_bytes(),
            height: height.to_le(),
            record_count: record_count.to_le(),
        };
        writer.write_all(header.as_bytes())?;

        for shard_idx in 0_u8..=u8::MAX {
            view.shard(usize::from(shard_idx)).with_table(|table| {
                for record in &table.table {
                    let vout_count = u8::try_from(record.output_count()).map_err(|_| {
                        UtxoError::SnapshotOutputCountTooLarge {
                            count: record.output_count(),
                        }
                    })?;
                    let record_header = SnapshotRecordHeaderV3 {
                        shard_idx,
                        key_prefix: record.key().to_prefix(),
                        txid: record.txid().to_le_bytes(),
                        vout_count,
                    };
                    writer.write_all(record_header.as_bytes())?;
                    for output in record.iter_outputs() {
                        let script = script_slice(table, output).ok_or(UtxoError::CorruptArena)?;
                        let vout_header = SnapshotVoutHeader {
                            vout: output.vout.to_le(),
                            value: output.value.to_le(),
                            height: output.height.to_le(),
                            coinbase: u8::from(output.coinbase),
                            script_len: output.script_pubkey_len.to_le(),
                        };
                        writer.write_all(vout_header.as_bytes())?;
                        writer.write_all(script)?;
                    }
                }
                Ok::<(), UtxoError>(())
            })?;
        }

        let trailer = view
            .listener_muhash3072()
            .unwrap_or([0_u8; MUHASH_TRAILER_LEN]);
        writer.write_all(&trailer)?;
        Ok(trailer)
    })
}

/// Streams a native bitcoin-rs UTXO snapshot from `reader` into a fresh set.
pub fn read_snapshot(reader: &mut impl Read) -> Result<SnapshotLoad, UtxoError> {
    let header_bytes = read_array::<{ core::mem::size_of::<SnapshotHeader>() }>(reader)?;
    let magic = read_u32(&header_bytes, 0);
    if magic != SNAPSHOT_MAGIC {
        return Err(UtxoError::InvalidSnapshotMagic { actual: magic });
    }
    let version = read_u32(&header_bytes, 4);
    if version != SNAPSHOT_LEGACY_VERSION && version != SNAPSHOT_WRITE_VERSION {
        return Err(UtxoError::UnsupportedSnapshotVersion { version });
    }
    let mut tip_hash = [0_u8; 32];
    tip_hash.copy_from_slice(&header_bytes[8..40]);
    let height = read_u32(&header_bytes, 40);
    let record_count = read_u64(&header_bytes, 44);
    let record_count_usize =
        usize::try_from(record_count).map_err(|_| UtxoError::SnapshotRecordCountTooLarge {
            count: record_count,
        })?;

    let set = UtxoSet::new();
    for _ in 0..record_count_usize {
        let (key, txid, outputs) = match version {
            SNAPSHOT_LEGACY_VERSION => read_snapshot_record_v2(reader)?,
            SNAPSHOT_WRITE_VERSION => read_snapshot_record_v3(reader)?,
            _ => unreachable!("snapshot version was validated"),
        };
        set.insert_snapshot_record(key, txid, &outputs)?;
    }

    let mut muhash_trailer = [0_u8; MUHASH_TRAILER_LEN];
    match reader.read_exact(&mut muhash_trailer) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(error.into()),
    }

    Ok(SnapshotLoad {
        set,
        tip_hash: Hash256::from_le_bytes(&tip_hash),
        height,
        muhash_trailer,
    })
}

fn read_snapshot_record_v2(
    reader: &mut impl Read,
) -> Result<(UtxoKey, Hash256, Vec<OwnedUtxoOut>), UtxoError> {
    let record_header_bytes =
        read_array::<{ core::mem::size_of::<SnapshotRecordHeader>() }>(reader)?;
    let shard_idx = record_header_bytes[0];
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&record_header_bytes[1..9]);
    let mut txid_bytes = [0_u8; 32];
    txid_bytes.copy_from_slice(&record_header_bytes[9..41]);
    let txid = Hash256::from_le_bytes(&txid_bytes);
    let key = UtxoKey::from_prefix(prefix);
    validate_snapshot_key(key, txid, shard_idx)?;
    let vout_bitmap = read_u64(&record_header_bytes, 41);
    let vout_count = record_header_bytes[49];
    if vout_bitmap.count_ones() != u32::from(vout_count) {
        return Err(UtxoError::SnapshotVoutCountMismatch {
            bitmap: vout_bitmap,
            vout_count,
        });
    }

    let mut outputs = Vec::with_capacity(usize::from(vout_count));
    for _ in 0..vout_count {
        let output = read_snapshot_output(reader)?;
        let Some(bit) = bitmap_vout_bit(output.vout) else {
            return Err(UtxoError::VoutOutOfRange { vout: output.vout });
        };
        if vout_bitmap & bit == 0 {
            return Err(UtxoError::SnapshotVoutBitmapMismatch {
                bitmap: vout_bitmap,
                vout: output.vout,
            });
        }
        reject_duplicate_vout(&outputs, output.vout)?;
        outputs.push(output);
    }
    Ok((key, txid, outputs))
}

fn read_snapshot_record_v3(
    reader: &mut impl Read,
) -> Result<(UtxoKey, Hash256, Vec<OwnedUtxoOut>), UtxoError> {
    let record_header_bytes =
        read_array::<{ core::mem::size_of::<SnapshotRecordHeaderV3>() }>(reader)?;
    let shard_idx = record_header_bytes[0];
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&record_header_bytes[1..9]);
    let mut txid_bytes = [0_u8; 32];
    txid_bytes.copy_from_slice(&record_header_bytes[9..41]);
    let txid = Hash256::from_le_bytes(&txid_bytes);
    let key = UtxoKey::from_prefix(prefix);
    validate_snapshot_key(key, txid, shard_idx)?;
    let vout_count = record_header_bytes[41];
    let mut outputs = Vec::with_capacity(usize::from(vout_count));
    for _ in 0..vout_count {
        let output = read_snapshot_output(reader)?;
        reject_duplicate_vout(&outputs, output.vout)?;
        outputs.push(output);
    }
    Ok((key, txid, outputs))
}

fn validate_snapshot_key(key: UtxoKey, txid: Hash256, shard_idx: u8) -> Result<(), UtxoError> {
    if UtxoKey::from_txid(&txid) != key {
        return Err(UtxoError::SnapshotTxidPrefixMismatch);
    }
    if key.shard() != shard_idx {
        return Err(UtxoError::SnapshotShardMismatch {
            shard: shard_idx,
            key_shard: key.shard(),
        });
    }
    Ok(())
}

fn read_snapshot_output(reader: &mut impl Read) -> Result<OwnedUtxoOut, UtxoError> {
    let vout_header_bytes = read_array::<{ core::mem::size_of::<SnapshotVoutHeader>() }>(reader)?;
    let vout = read_u32(&vout_header_bytes, 0);
    let value = read_u64(&vout_header_bytes, 4);
    let height = read_u32(&vout_header_bytes, 12);
    let coinbase = vout_header_bytes[16] != 0;
    let script_len = read_u16(&vout_header_bytes, 17);
    let mut script = vec![0_u8; usize::from(script_len)];
    reader.read_exact(&mut script)?;
    Ok(OwnedUtxoOut::new(vout, value, script, coinbase, height))
}

fn reject_duplicate_vout(outputs: &[OwnedUtxoOut], vout: u32) -> Result<(), UtxoError> {
    if outputs.iter().any(|output| output.vout == vout) {
        Err(UtxoError::SnapshotDuplicateVout { vout })
    } else {
        Ok(())
    }
}

/// Computes Bitcoin Core's `hash_serialized_3` UTXO-set commitment.
pub fn hash_serialized_3(set: &UtxoSet) -> Result<Hash256, UtxoError> {
    set.with_stable_view(hash_serialized_3_stable)
}

pub(crate) fn hash_serialized_3_stable(view: &UtxoSetView<'_>) -> Result<Hash256, UtxoError> {
    let mut engine = Sha256::new();
    for shard_idx in 0_u8..=u8::MAX {
        view.shard(usize::from(shard_idx)).with_table(|table| {
            let mut entries = Vec::with_capacity(table.output_count());
            for record in &table.table {
                for output in record.iter_outputs() {
                    let script = script_slice(table, output).ok_or(UtxoError::CorruptArena)?;
                    entries.push(HashSerializedEntry {
                        txid_le: record.txid().to_le_bytes(),
                        output,
                        script,
                    });
                }
            }

            entries.sort_unstable_by(|left, right| {
                left.txid_le
                    .cmp(&right.txid_le)
                    .then_with(|| left.output.vout.cmp(&right.output.vout))
            });

            for entry in entries {
                engine.update(entry.txid_le);
                engine.update(entry.output.vout.to_le_bytes());
                let code = (entry.output.height << 1) | u32::from(entry.output.coinbase);
                engine.update(code.to_le_bytes());
                engine.update(entry.output.value.to_le_bytes());
                let script_len =
                    u64::try_from(entry.script.len()).map_err(|_| UtxoError::ScriptTooLarge {
                        len: entry.script.len(),
                    })?;
                let encoded_len = varint::encode(script_len);
                engine.update(encoded_len.as_slice());
                engine.update(entry.script);
            }
            Ok::<(), UtxoError>(())
        })?;
    }

    let first = engine.finalize();
    let second = Sha256::digest(first);
    let bytes: [u8; 32] = second.into();
    Ok(Hash256::from_le_bytes(&bytes))
}

impl UtxoSetView<'_> {
    /// Invokes `f` once per live coin in the stable view, passing
    /// `(txid, vout, value, script_pubkey, height, coinbase)`. The script slice
    /// borrows arena memory valid only for the duration of the call.
    ///
    /// On-demand scan helper (e.g. `gettxoutsetinfo`); not on any hot path.
    pub fn for_each_coin<F>(&self, mut f: F) -> Result<(), UtxoError>
    where
        F: FnMut(Hash256, u32, u64, &[u8], u32, bool),
    {
        for shard_idx in 0_u8..=u8::MAX {
            self.shard(usize::from(shard_idx)).with_table(|table| {
                for record in &table.table {
                    let txid = record.txid();
                    for output in record.iter_outputs() {
                        let script = script_slice(table, output).ok_or(UtxoError::CorruptArena)?;
                        f(
                            txid,
                            output.vout,
                            output.value,
                            script,
                            output.height,
                            output.coinbase,
                        );
                    }
                }
                Ok::<(), UtxoError>(())
            })?;
        }
        Ok(())
    }
}

/// Computes a deterministic aggregate hash over sorted live UTXO entries.
pub fn aggregate_hash(set: &UtxoSet) -> Result<Hash256, UtxoError> {
    hash_serialized_3(set)
}

struct HashSerializedEntry<'a> {
    txid_le: [u8; 32],
    output: &'a OneUtxoOut,
    script: &'a [u8],
}

fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], UtxoError> {
    let mut bytes = [0_u8; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut out = [0_u8; 2];
    out.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(out)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut out = [0_u8; 4];
    out.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(out)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut out = [0_u8; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(out)
}

fn script_slice<'table>(
    table: &'table ShardTable<'_>,
    output: &OneUtxoOut,
) -> Option<&'table [u8]> {
    let start = usize::try_from(output.script_pubkey_offset).ok()?;
    let len = usize::from(output.script_pubkey_len);
    let end = start.checked_add(len)?;
    table.script_bytes.get(start..end)
}
