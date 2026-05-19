use std::io::{Read, Write};

use bitcoin_rs_primitives::Hash256;
use sha2::{Digest, Sha256};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    UtxoError, UtxoKey, UtxoSet,
    record::{OneUtxoOut, OwnedUtxoOut},
    shard::ShardTable,
};

const SNAPSHOT_MAGIC: u32 = 0x55_54_58_4f;
const SNAPSHOT_VERSION: u32 = 1;
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
    vout_bitmap: u64,
    vout_count: u8,
}

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct SnapshotVoutHeader {
    vout: u32,
    value: u64,
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
    let record_count = u64::try_from(set.record_count())
        .map_err(|_| UtxoError::SnapshotRecordCountTooLarge { count: u64::MAX })?;
    let header = SnapshotHeader {
        magic: SNAPSHOT_MAGIC.to_le(),
        version: SNAPSHOT_VERSION.to_le(),
        tip_hash: tip_hash.to_le_bytes(),
        height: height.to_le(),
        record_count: record_count.to_le(),
    };
    writer.write_all(header.as_bytes())?;

    for shard_idx in 0_u8..=u8::MAX {
        set.shard(usize::from(shard_idx)).with_table(|table| {
            for record in &table.table {
                let vout_count = u8::try_from(record.output_count()).map_err(|_| {
                    UtxoError::SnapshotOutputCountTooLarge {
                        count: record.output_count(),
                    }
                })?;
                let record_header = SnapshotRecordHeader {
                    shard_idx,
                    key_prefix: record.key().to_prefix(),
                    vout_bitmap: record.vout_bitmap.to_le(),
                    vout_count,
                };
                writer.write_all(record_header.as_bytes())?;
                for output in record.iter_outputs() {
                    let script = script_slice(table, output).ok_or(UtxoError::CorruptArena)?;
                    let vout_header = SnapshotVoutHeader {
                        vout: output.vout.to_le(),
                        value: output.value.to_le(),
                        script_len: output.script_pubkey_len.to_le(),
                    };
                    writer.write_all(vout_header.as_bytes())?;
                    writer.write_all(script)?;
                }
            }
            Ok::<(), UtxoError>(())
        })?;
    }

    let trailer = set
        .listener_muhash3072()
        .unwrap_or([0_u8; MUHASH_TRAILER_LEN]);
    writer.write_all(&trailer)?;
    Ok(trailer)
}

/// Streams a native bitcoin-rs UTXO snapshot from `reader` into a fresh set.
pub fn read_snapshot(reader: &mut impl Read) -> Result<SnapshotLoad, UtxoError> {
    let header_bytes = read_array::<{ core::mem::size_of::<SnapshotHeader>() }>(reader)?;
    let magic = read_u32(&header_bytes, 0);
    if magic != SNAPSHOT_MAGIC {
        return Err(UtxoError::InvalidSnapshotMagic { actual: magic });
    }
    let version = read_u32(&header_bytes, 4);
    if version != SNAPSHOT_VERSION {
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
        let record_header_bytes =
            read_array::<{ core::mem::size_of::<SnapshotRecordHeader>() }>(reader)?;
        let shard_idx = record_header_bytes[0];
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&record_header_bytes[1..9]);
        let key = UtxoKey::from_prefix(prefix);
        if key.shard() != shard_idx {
            return Err(UtxoError::SnapshotShardMismatch {
                shard: shard_idx,
                key_shard: key.shard(),
            });
        }
        let vout_bitmap = read_u64(&record_header_bytes, 9);
        let vout_count = record_header_bytes[17];
        if vout_bitmap.count_ones() != u32::from(vout_count) {
            return Err(UtxoError::SnapshotVoutCountMismatch {
                bitmap: vout_bitmap,
                vout_count,
            });
        }

        let mut outputs = Vec::with_capacity(usize::from(vout_count));
        for _ in 0..vout_count {
            let vout_header_bytes =
                read_array::<{ core::mem::size_of::<SnapshotVoutHeader>() }>(reader)?;
            let vout = read_u32(&vout_header_bytes, 0);
            let value = read_u64(&vout_header_bytes, 4);
            let script_len = read_u16(&vout_header_bytes, 12);
            let mut script = vec![0_u8; usize::from(script_len)];
            reader.read_exact(&mut script)?;
            outputs.push(OwnedUtxoOut::new(vout, value, script, false, 0));
        }
        set.insert_snapshot_record(key, &outputs)?;
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

/// Computes a deterministic aggregate hash over sorted live UTXO entries.
pub fn aggregate_hash(set: &UtxoSet) -> Result<Hash256, UtxoError> {
    let mut entries = Vec::with_capacity(set.len());
    for shard_idx in 0_u8..=u8::MAX {
        set.shard(usize::from(shard_idx)).with_table(|table| {
            for record in &table.table {
                for output in record.iter_outputs() {
                    let script = script_slice(table, output).ok_or(UtxoError::CorruptArena)?;
                    entries.push(AggregateEntry {
                        key: record.key().to_prefix(),
                        vout: output.vout,
                        value: output.value,
                        script: script.to_vec(),
                    });
                }
            }
            Ok::<(), UtxoError>(())
        })?;
    }
    entries.sort_unstable_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.vout.cmp(&right.vout))
    });

    let mut engine = Sha256::new();
    for entry in entries {
        engine.update(entry.key);
        engine.update(entry.vout.to_le_bytes());
        engine.update(entry.value.to_le_bytes());
        let script_len =
            u64::try_from(entry.script.len()).map_err(|_| UtxoError::ScriptTooLarge {
                len: entry.script.len(),
            })?;
        engine.update(script_len.to_le_bytes());
        engine.update(entry.script);
    }
    let first = engine.finalize();
    let second = Sha256::digest(first);
    let bytes: [u8; 32] = second.into();
    Ok(Hash256::from_le_bytes(&bytes))
}

struct AggregateEntry {
    key: [u8; 8],
    vout: u32,
    value: u64,
    script: Vec<u8>,
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
