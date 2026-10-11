use std::io::{Read, Write};

use bitcoin_rs_primitives::{Hash256, Txid, varint};
use hashbrown::HashSet;
use sha2::{Digest, Sha256};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    UtxoError, UtxoKey, UtxoSet, UtxoSetView,
    record::{OneUtxoOut, OwnedUtxoOut, UtxoRecord},
};

const SNAPSHOT_MAGIC: u32 = 0x55_54_58_4f;
const SNAPSHOT_WRITE_VERSION: u32 = 4;
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
struct SnapshotRecordHeaderV4 {
    shard_idx: u8,
    key_prefix: [u8; 8],
    txid: [u8; 32],
    output_count: u32,
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

/// A live coin borrowed while a snapshot is traversed.
#[derive(Copy, Clone)]
pub struct SnapshotCoin<'a> {
    /// Transaction identifier that created this output.
    pub txid: Hash256,
    /// Originating transaction output index.
    pub vout: u32,
    /// Output value in satoshis.
    pub value: u64,
    /// Borrowed scriptPubKey bytes.
    pub script_pubkey: &'a [u8],
    /// Block height that created the output.
    pub height: u32,
    /// Whether the originating transaction was coinbase.
    pub coinbase: bool,
}

/// Observes each live coin traversed by snapshot serialization or strict loading.
pub trait SnapshotCoinObserver {
    /// Observes one live coin.
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>);

    /// Selects the final snapshot trailer, defaulting to the supplied fallback.
    fn select_trailer(&mut self, fallback: [u8; MUHASH_TRAILER_LEN]) -> [u8; MUHASH_TRAILER_LEN] {
        fallback
    }
}

impl SnapshotCoinObserver for () {
    fn observe_coin(&mut self, _: SnapshotCoin<'_>) {}
}

/// Streams a native bitcoin-rs UTXO snapshot while observing every live coin.
pub fn write_snapshot_observed<O: SnapshotCoinObserver, W: Write + ?Sized>(
    set: &UtxoSet,
    tip_hash: &Hash256,
    height: u32,
    writer: &mut W,
    mut observer: O,
) -> Result<([u8; MUHASH_TRAILER_LEN], O), UtxoError> {
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
                    let output_count = u32::try_from(record.output_count()).map_err(|_| {
                        UtxoError::SnapshotOutputCountTooLarge {
                            count: record.output_count(),
                        }
                    })?;
                    let txid = record.txid();
                    let record_header = SnapshotRecordHeaderV4 {
                        shard_idx,
                        key_prefix: record.key().to_prefix(),
                        txid: txid.to_le_bytes(),
                        output_count: output_count.to_le(),
                    };
                    writer.write_all(record_header.as_bytes())?;
                    for output in record.outputs() {
                        let script_len =
                            u16::try_from(output.script_pubkey.len()).map_err(|_| {
                                UtxoError::ScriptTooLarge {
                                    len: output.script_pubkey.len(),
                                }
                            })?;
                        let vout_header = SnapshotVoutHeader {
                            vout: output.vout.to_le(),
                            value: output.value.to_le(),
                            height: output.height.to_le(),
                            coinbase: u8::from(output.coinbase),
                            script_len: script_len.to_le(),
                        };
                        writer.write_all(vout_header.as_bytes())?;
                        writer.write_all(output.script_pubkey)?;
                        observer.observe_coin(SnapshotCoin {
                            txid,
                            vout: output.vout,
                            value: output.value,
                            script_pubkey: output.script_pubkey,
                            height: output.height,
                            coinbase: output.coinbase,
                        });
                    }
                }
                Ok::<(), UtxoError>(())
            })?;
        }

        let fallback = view
            .listener_muhash3072()
            .unwrap_or([0_u8; MUHASH_TRAILER_LEN]);
        let trailer = observer.select_trailer(fallback);
        writer.write_all(&trailer)?;
        Ok((trailer, observer))
    })
}

/// Parsed native-v4 header identity; this does not validate the coin body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeSnapshotMetadata {
    /// Snapshot base block identity.
    pub tip_hash: Hash256,
    /// Snapshot base height.
    pub height: u32,
    /// Declared transaction-level records, not output count.
    pub record_count: u64,
}

/// Reads the fixed native-v4 header through the same parser as checkpoint load.
/// Intended for bounded identification; callers must not treat it as full
/// snapshot verification or as a trust anchor.
pub fn read_snapshot_metadata_v4(
    reader: &mut impl Read,
) -> Result<NativeSnapshotMetadata, UtxoError> {
    let header_bytes = read_array::<{ core::mem::size_of::<SnapshotHeader>() }>(reader)?;
    let magic = read_u32(&header_bytes, 0);
    if magic != SNAPSHOT_MAGIC {
        return Err(UtxoError::InvalidSnapshotMagic { actual: magic });
    }
    let version = read_u32(&header_bytes, 4);
    if version != SNAPSHOT_WRITE_VERSION {
        return Err(UtxoError::UnsupportedSnapshotVersion { version });
    }
    let mut tip_hash = [0_u8; 32];
    tip_hash.copy_from_slice(&header_bytes[8..40]);
    let height = read_u32(&header_bytes, 40);
    let record_count = read_u64(&header_bytes, 44);
    Ok(NativeSnapshotMetadata {
        tip_hash: Hash256::from_le_bytes(&tip_hash),
        height,
        record_count,
    })
}

/// Strictly decodes a complete v4 snapshot for a chainstate checkpoint.
pub fn read_snapshot_strict_v4(reader: &mut impl Read) -> Result<SnapshotLoad, UtxoError> {
    read_snapshot_strict_v4_observed(reader, ()).map(|(snapshot, ())| snapshot)
}

/// Strictly decodes a complete v4 snapshot while observing each inserted coin.
pub fn read_snapshot_strict_v4_observed<O: SnapshotCoinObserver>(
    reader: &mut impl Read,
    mut observer: O,
) -> Result<(SnapshotLoad, O), UtxoError> {
    let NativeSnapshotMetadata {
        tip_hash,
        height,
        record_count,
    } = read_snapshot_metadata_v4(reader)?;
    let record_count_usize =
        usize::try_from(record_count).map_err(|_| UtxoError::SnapshotRecordCountTooLarge {
            count: record_count,
        })?;

    let set = UtxoSet::new();
    let mut seen_vouts = HashSet::new();
    for _ in 0..record_count_usize {
        let (txid, outputs) = read_snapshot_record_v4(reader, &mut seen_vouts)?;
        set.insert_snapshot_record(UtxoRecord::from_owned_outputs(txid, &outputs)?);
        for output in &outputs {
            observer.observe_coin(SnapshotCoin {
                txid,
                vout: output.vout,
                value: output.value,
                script_pubkey: &output.script_pubkey,
                height: output.height,
                coinbase: output.coinbase,
            });
        }
    }

    let actual = set.record_count();
    if actual != record_count_usize {
        return Err(UtxoError::SnapshotRecordCountMismatch {
            declared: record_count,
            actual,
        });
    }

    let mut muhash_trailer = [0_u8; MUHASH_TRAILER_LEN];
    reader.read_exact(&mut muhash_trailer)?;
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snapshot has trailing bytes",
        )
        .into());
    }

    Ok((
        SnapshotLoad {
            set,
            tip_hash,
            height,
            muhash_trailer,
        },
        observer,
    ))
}

fn read_snapshot_record_v4(
    reader: &mut impl Read,
    seen_vouts: &mut HashSet<u32>,
) -> Result<(Hash256, Vec<OwnedUtxoOut>), UtxoError> {
    let record_header_bytes =
        read_array::<{ core::mem::size_of::<SnapshotRecordHeaderV4>() }>(reader)?;
    let txid = decode_record_identity(&record_header_bytes)?;
    let outputs = read_snapshot_outputs(reader, read_u32(&record_header_bytes, 41), seen_vouts)?;
    Ok((txid, outputs))
}

fn decode_record_identity(header: &[u8]) -> Result<Hash256, UtxoError> {
    let shard_idx = header[0];
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&header[1..9]);
    let mut txid_bytes = [0_u8; 32];
    txid_bytes.copy_from_slice(&header[9..41]);
    let txid = Hash256::from_le_bytes(&txid_bytes);
    let key = UtxoKey::from_prefix(prefix);
    validate_snapshot_key(key, txid, shard_idx)?;
    Ok(txid)
}

fn read_snapshot_outputs(
    reader: &mut impl Read,
    output_count: u32,
    seen_vouts: &mut HashSet<u32>,
) -> Result<Vec<OwnedUtxoOut>, UtxoError> {
    // The declared count is untrusted; grow only after bytes for an output arrive.
    seen_vouts.clear();
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let output = read_snapshot_output(reader)?;
        if !seen_vouts.insert(output.vout) {
            return Err(UtxoError::SnapshotDuplicateVout { vout: output.vout });
        }
        outputs.push(output);
    }
    Ok(outputs)
}

fn validate_snapshot_key(key: UtxoKey, txid: Hash256, shard_idx: u8) -> Result<(), UtxoError> {
    if UtxoKey::from_txid(&Txid::from(txid)) != key {
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

/// Computes Bitcoin Core's `hash_serialized_3` UTXO-set commitment over a
/// stable view.
pub(crate) fn hash_serialized_3_stable(view: &UtxoSetView<'_>) -> Result<Hash256, UtxoError> {
    hash_serialized_3_stable_inner(view, None)
}

/// Commitment with the additional creation-height rule required by `AssumeUTXO`.
pub(crate) fn hash_serialized_3_stable_at_height(
    view: &UtxoSetView<'_>,
    snapshot_height: u32,
) -> Result<Hash256, UtxoError> {
    hash_serialized_3_stable_inner(view, Some(snapshot_height))
}

fn hash_serialized_3_stable_inner(
    view: &UtxoSetView<'_>,
    snapshot_height: Option<u32>,
) -> Result<Hash256, UtxoError> {
    let mut engine = SerializedUtxoHasher::new();
    for shard_idx in 0_u8..=u8::MAX {
        view.shard(usize::from(shard_idx)).with_table(|table| {
            let mut entries = Vec::with_capacity(table.output_count());
            for record in &table.table {
                for output in record.outputs() {
                    entries.push(HashSerializedEntry {
                        txid_le: record.txid().to_le_bytes(),
                        output,
                    });
                }
            }

            entries.sort_unstable_by(|left, right| {
                left.txid_le
                    .cmp(&right.txid_le)
                    .then_with(|| left.output.vout.cmp(&right.output.vout))
            });

            for entry in entries {
                engine.add(entry.txid_le, entry.output, snapshot_height)?;
            }
            Ok::<(), UtxoError>(())
        })?;
    }

    Ok(engine.finish())
}

/// The single per-coin serialization owner for Core's `HASH_SERIALIZED`
/// commitment. Callers supply coins in raw-txid, numeric-vout order.
pub(crate) struct SerializedUtxoHasher(Sha256);

impl SerializedUtxoHasher {
    pub(crate) fn new() -> Self {
        Self(Sha256::new())
    }

    pub(crate) fn add(
        &mut self,
        txid_le: [u8; 32],
        output: OneUtxoOut<'_>,
        snapshot_height: Option<u32>,
    ) -> Result<(), UtxoError> {
        if let Some(snapshot_height) = snapshot_height
            && output.height > snapshot_height
        {
            return Err(UtxoError::SnapshotCoinHeightOutOfRange {
                height: output.height,
                snapshot_height,
            });
        }
        self.0.update(txid_le);
        self.0.update(output.vout.to_le_bytes());
        let code = (output.height << 1) | u32::from(output.coinbase);
        self.0.update(code.to_le_bytes());
        self.0.update(output.value.to_le_bytes());
        let script_len =
            u64::try_from(output.script_pubkey.len()).map_err(|_| UtxoError::ScriptTooLarge {
                len: output.script_pubkey.len(),
            })?;
        self.0.update(varint::encode(script_len).as_slice());
        self.0.update(output.script_pubkey);
        Ok(())
    }

    pub(crate) fn finish(self) -> Hash256 {
        let first = self.0.finalize();
        let second = Sha256::digest(first);
        let bytes: [u8; 32] = second.into();
        Hash256::from_le_bytes(&bytes)
    }
}

impl UtxoSetView<'_> {
    /// Invokes `f` once per live coin in the stable view. The script slice
    /// borrows the record payload only for the duration of the call.
    ///
    /// On-demand scan helper (e.g. `gettxoutsetinfo`); not on any hot path.
    pub(crate) fn for_each_coin<F>(&self, mut f: F) -> Result<(), UtxoError>
    where
        F: FnMut(SnapshotCoin<'_>),
    {
        for shard_idx in 0_u8..=u8::MAX {
            self.shard(usize::from(shard_idx)).with_table(|table| {
                for record in &table.table {
                    let txid = record.txid();
                    for output in record.outputs() {
                        f(SnapshotCoin {
                            txid,
                            vout: output.vout,
                            value: output.value,
                            script_pubkey: output.script_pubkey,
                            height: output.height,
                            coinbase: output.coinbase,
                        });
                    }
                }
                Ok::<(), UtxoError>(())
            })?;
        }
        Ok(())
    }
}

struct HashSerializedEntry<'a> {
    txid_le: [u8; 32],
    output: OneUtxoOut<'a>,
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
