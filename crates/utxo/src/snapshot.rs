use std::io::{Read, Seek, Write};

use bitcoin_rs_primitives::{Hash256, OutPoint, Txid, varint};
use bitcoin_rs_storage::checkpoint::CheckpointReference;
use hashbrown::HashSet;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use thiserror::Error;
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
    observer: O,
) -> Result<([u8; MUHASH_TRAILER_LEN], O), UtxoError> {
    set.with_stable_view(|view| {
        let (trailer, observer, _audit) =
            write_snapshot_view(view, tip_hash, height, writer, observer)?;
        Ok((trailer, observer))
    })
}

/// Shared native-v4 encoding traversal: header, shard-ordered records, trailer.
/// Runs under the caller's stable view; the witnessed writer mints only when
/// the returned audit shows a complete stream with no empty record.
fn write_snapshot_view<O: SnapshotCoinObserver, W: Write + ?Sized>(
    view: &UtxoSetView<'_>,
    tip_hash: &Hash256,
    height: u32,
    writer: &mut W,
    mut observer: O,
) -> Result<([u8; MUHASH_TRAILER_LEN], O, WriteAudit), UtxoError> {
    let record_count = u64::try_from(view.record_count())
        .map_err(|_| UtxoError::SnapshotRecordCountTooLarge { count: u64::MAX })?;
    let mut audit = WriteAudit {
        declared_records: record_count,
        emitted_records: 0,
        emitted_outputs: 0,
        empty_record: false,
    };
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
                audit.emitted_records += 1;
                audit.emitted_outputs += u64::from(output_count);
                if output_count == 0 {
                    audit.empty_record = true;
                }
                let txid = record.txid();
                let record_header = SnapshotRecordHeaderV4 {
                    shard_idx,
                    key_prefix: record.key().to_prefix(),
                    txid: txid.to_le_bytes(),
                    output_count: output_count.to_le(),
                };
                writer.write_all(record_header.as_bytes())?;
                for output in record.outputs() {
                    let script_len = u16::try_from(output.script_pubkey.len()).map_err(|_| {
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
    Ok((trailer, observer, audit))
}

/// Outcome of the witnessed encode audit: what the header declared versus
/// what the traversal actually emitted.
struct WriteAudit {
    declared_records: u64,
    emitted_records: u64,
    emitted_outputs: u64,
    empty_record: bool,
}

/// Streams a native snapshot exactly like [`write_snapshot_observed`] while
/// hashing every emitted byte, and mints a [`V4Witness`] binding those bytes
/// to the accepted chainstate.
///
/// The witness is `None` (no mint) when the traversal observed an emitted
/// count mismatch or an empty record; the bytes are still written exactly as
/// the plain path writes them.
pub fn write_snapshot_witnessed<O: SnapshotCoinObserver, W: Write + ?Sized>(
    set: &UtxoSet,
    tip_hash: &Hash256,
    height: u32,
    writer: &mut W,
    observer: O,
) -> Result<([u8; MUHASH_TRAILER_LEN], O, Option<V4Witness>), UtxoError> {
    set.with_stable_view(|view| {
        let mut tee = TeeWriter::new(writer);
        let (trailer, observer, audit) =
            write_snapshot_view(view, tip_hash, height, &mut tee, observer)?;
        let (sha256, len) = tee.finish();
        let complete = !audit.empty_record && audit.emitted_records == audit.declared_records;
        let witness = complete.then_some(V4Witness {
            len,
            sha256,
            tip_hash: *tip_hash,
            height,
            record_count: audit.declared_records,
            output_count: audit.emitted_outputs,
            origin: Origin::Encoded,
        });
        Ok((trailer, observer, witness))
    })
}

/// Counts and hashes every byte passing through to the wrapped writer.
struct TeeWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    hasher: Sha256,
    len: u64,
}

impl<'a, W: Write + ?Sized> TeeWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            len: 0,
        }
    }

    fn finish(self) -> ([u8; 32], u64) {
        (self.hasher.finalize().into(), self.len)
    }
}

impl<W: Write + ?Sized> Write for TeeWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.len = count_bytes(self.len, written)?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Adds one transfer length to a running byte count without lossy casts.
fn count_bytes(len: u64, transfer: usize) -> std::io::Result<u64> {
    let count = u64::try_from(transfer)
        .map_err(|_| std::io::Error::other("snapshot byte count overflow"))?;
    len.checked_add(count)
        .ok_or_else(|| std::io::Error::other("snapshot byte count overflow"))
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

/// Strictly decodes a complete v4 snapshot while minting a byte-binding witness.
///
/// Behaves exactly like [`read_snapshot_strict_v4_observed`], additionally
/// hashing every consumed byte (header, records, trailer) through the exact
/// end-of-stream probe and minting a [`V4Witness`] bound to those bytes.
///
/// The caller keeps ownership of its reader throughout, so unwrapping the
/// same adapter stack back to the underlying `File` and sealing that
/// descriptor pins the accepted bytes to the sealed descriptor: no reopen
/// by path.
pub fn read_snapshot_strict_v4_witnessed<O: SnapshotCoinObserver>(
    reader: &mut impl Read,
    observer: O,
) -> Result<(SnapshotLoad, O, V4Witness), UtxoError> {
    let mut tee = TeeReader::new(reader);
    let (load, observer) = read_snapshot_strict_v4_observed(&mut tee, observer)?;
    let (sha256, len) = tee.finish();
    let record_count = u64::try_from(load.set.record_count())
        .map_err(|_| UtxoError::SnapshotRecordCountTooLarge { count: u64::MAX })?;
    let output_count = u64::try_from(load.set.len())
        .map_err(|_| UtxoError::SnapshotRecordCountTooLarge { count: u64::MAX })?;
    let witness = V4Witness {
        len,
        sha256,
        tip_hash: load.tip_hash,
        height: load.height,
        record_count,
        output_count,
        origin: Origin::Decoded,
    };
    Ok((load, observer, witness))
}

/// Reads one v4 record head: framing bytes, identity, and declared output
/// count. Shared by the strict loader (which then reads the full record)
/// and the raw seed stream (which then reads outputs one at a time), so the
/// framing lives in exactly one place.
fn read_snapshot_record_head(reader: &mut impl Read) -> Result<(Hash256, u32), UtxoError> {
    let record_header_bytes =
        read_array::<{ core::mem::size_of::<SnapshotRecordHeaderV4>() }>(reader)?;
    let txid = decode_record_identity(&record_header_bytes)?;
    Ok((txid, read_u32(&record_header_bytes, 41)))
}

fn read_snapshot_record_v4(
    reader: &mut impl Read,
    seen_vouts: &mut HashSet<u32>,
) -> Result<(Hash256, Vec<OwnedUtxoOut>), UtxoError> {
    let (txid, output_count) = read_snapshot_record_head(reader)?;
    let outputs = read_snapshot_outputs(reader, output_count, seen_vouts)?;
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

// ---------------------------------------------------------------------------
// Witnessed snapshot artifacts and the worker-owned seed cell.
// ---------------------------------------------------------------------------

/// Proof that exactly these bytes passed strict v4 decode. Only `utxo` mints.
///
/// The witness binds the exact accepted byte stream: any substitution,
/// truncation, or trailing-byte append between the accepted load and a later
/// raw traversal fails the length/digest comparison in
/// [`VerifiedSnapshotArtifact::for_each_coin_raw`].
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V4Witness {
    len: u64,
    sha256: [u8; 32],
    tip_hash: Hash256,
    height: u32,
    record_count: u64,
    output_count: u64,
    origin: Origin,
}

/// Which direction minted the witness: strict decode of stored bytes, or
/// encode of the live set. Private: callers observe the mint direction
/// through [`V4Witness::is_decoded`], never the enumerant itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    Decoded,
    Encoded,
}

impl V4Witness {
    /// Exact byte length hashed (header, records, trailer).
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.len
    }

    /// SHA-256 over every consumed/emitted byte, including the trailer.
    #[must_use]
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// Snapshot base block identity the witnessed bytes were accepted at.
    #[must_use]
    pub fn tip_hash(&self) -> Hash256 {
        self.tip_hash
    }

    /// Snapshot base height the witnessed bytes were accepted at.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Declared (and, on mint, actually emitted/decoded) transaction records.
    #[must_use]
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Total live outputs across all records.
    #[must_use]
    pub fn output_count(&self) -> u64 {
        self.output_count
    }

    /// Whether this witness was minted by strict decode (as opposed to encode).
    #[must_use]
    pub fn is_decoded(&self) -> bool {
        self.origin == Origin::Decoded
    }
}

/// Diagnostic identity of the chainstate that accepted the sealed bytes.
/// Carries no consensus meaning; the byte digest in [`V4Witness`] is the
/// binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedProvenance {
    /// Bytes published by a checkpoint generation.
    Checkpoint(CheckpointReference),
    /// Bytes staged by an `AssumeUTXO` activation for the given base block hash.
    AssumeUtxoArchive {
        /// Little-endian base block hash the archive was staged for.
        base: [u8; 32],
    },
}

/// Failure of the raw seed traversal.
///
/// `Integrity` covers every byte-binding failure (parse, length, digest,
/// truncation, trailing bytes); `Io` covers transport failures that a retry
/// may heal; `Emit` forwards the caller's own abort.
#[derive(Debug, Error)]
pub enum RawSeedError<E> {
    /// The artifact bytes are not exactly the witnessed accepted state.
    #[error("seed artifact bytes do not match the witness")]
    Integrity,
    /// Reading the artifact failed without impugning its bytes.
    #[error("seed artifact read failed: {0}")]
    Io(#[from] std::io::Error),
    /// The caller's `emit` closure failed.
    #[error("seed emit failed: {0}")]
    Emit(E),
}

/// One immutable native-v4 artifact whose bytes the authoritative chainstate
/// accepted. Not `Clone`: descriptors are never duplicated (a cloned `File`
/// would share its offset).
///
/// The file is the same descriptor the strict load consumed; raw traversal
/// seeks it back to the start, so sealing must move—not reopen—the verified
/// descriptor.
pub struct VerifiedSnapshotArtifact {
    file: std::fs::File,
    witness: V4Witness,
    provenance: SeedProvenance,
}

impl VerifiedSnapshotArtifact {
    /// Seals an accepted artifact.
    ///
    /// PRE: the caller accepted the decoded state as its chainstate at the
    /// witness height and tip. Only constructible with a [`V4Witness`]
    /// minted in this module, so the pairing is unforgeable.
    #[must_use]
    pub fn seal(file: std::fs::File, witness: V4Witness, provenance: SeedProvenance) -> Self {
        Self {
            file,
            witness,
            provenance,
        }
    }

    /// Base height and tip hash the sealed bytes were accepted at.
    #[must_use]
    pub fn tip(&self) -> (u32, Hash256) {
        (self.witness.height, self.witness.tip_hash)
    }

    /// Diagnostic identity of the accepting chainstate.
    #[must_use]
    pub fn provenance(&self) -> SeedProvenance {
        self.provenance
    }

    /// Replays every accepted coin in snapshot order through the caller's
    /// `emit`, which must keep its effects invisible until its own commit.
    ///
    /// Seeks the sealed descriptor to the start and streams records with the
    /// same parser as the strict loader, emitting `(outpoint, script_pubkey)`
    /// per live output. Succeeds only when the streamed length, digest, tip,
    /// height, and coin counts match the witness exactly; any parse, length,
    /// digest, truncation, or trailing-byte failure returns
    /// [`RawSeedError::Integrity`]. No second UTXO set is built: outputs
    /// stream through one at a time, each bounded by the v4 output encoding
    /// (19-byte header plus a script of at most 65,535 bytes). Reads are
    /// capped at the witnessed length plus one probe byte, so a file that
    /// grows concurrently cannot extend the traversal.
    pub fn for_each_coin_raw<E, F: FnMut(&OutPoint, &[u8]) -> Result<(), E> + ?Sized>(
        &mut self,
        emit: &mut F,
    ) -> Result<(), RawSeedError<E>> {
        self.file.rewind().map_err(RawSeedError::Io)?;
        let limit = self
            .witness
            .byte_len()
            .checked_add(1)
            .ok_or(RawSeedError::Integrity)?;
        let mut capped = Read::by_ref(&mut self.file).take(limit);
        let mut tee = TeeReader::new(&mut capped);
        let stream = read_raw_snapshot_stream(&mut tee, emit)?;
        let (digest, len) = tee.finish();
        let bound = len == self.witness.len
            && digest == self.witness.sha256
            && stream.tip_hash == self.witness.tip_hash
            && stream.height == self.witness.height
            && stream.records == self.witness.record_count
            && stream.outputs == self.witness.output_count;
        if !bound {
            return Err(RawSeedError::Integrity);
        }
        Ok(())
    }
}

/// Shared handle to the worker-owned seed cell. Cloned (not rebuilt) across
/// the publisher, control, and worker spec that belong to one process open,
/// so offers land exactly where the worker takes from.
pub type SeedOfferCell = std::sync::Arc<SeedSlot>;

/// Worker-owned demand plus at most one queued artifact.
///
/// States: `(false, None)` dormant, `(true, None)` wanted, `(true, Some)`
/// offered. `(false, Some)` never occurs: `take` clears demand with the
/// artifact, and `offer` stores only under demand.
///
/// The mutex covers pointer moves only. No open, read, hash, or commit ever
/// runs under it; descriptor closes happen after the lock is released.
pub struct SeedSlot {
    inner: Mutex<SeedCell>,
}

struct SeedCell {
    demand: bool,
    artifact: Option<VerifiedSnapshotArtifact>,
}

/// Whether an offered artifact was queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferOutcome {
    /// Demand was set and the cell was empty; the artifact is now queued.
    Stored,
    /// Demand was unset or the cell was occupied; the artifact was dropped
    /// and its descriptor closed without storing or reading.
    Skipped,
}

impl SeedSlot {
    /// Sole cross-crate constructor; starts empty with no demand.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SeedCell {
                demand: false,
                artifact: None,
            }),
        }
    }

    /// True iff demand is set and no artifact is queued.
    #[must_use]
    pub fn is_wanted(&self) -> bool {
        let cell = self.inner.lock();
        cell.demand && cell.artifact.is_none()
    }

    /// Declares demand when the cell is empty and undemanded. No-op otherwise.
    pub fn want(&self) {
        let mut cell = self.inner.lock();
        if !cell.demand && cell.artifact.is_none() {
            cell.demand = true;
        }
    }

    /// Clears demand and drops any queued artifact, closing its descriptor.
    pub fn rest(&self) {
        let dropped = {
            let mut cell = self.inner.lock();
            cell.demand = false;
            cell.artifact.take()
        };
        drop(dropped);
    }

    /// Stores the artifact iff demand is set and the cell is empty; otherwise
    /// drops it and closes its descriptor. Pure pointer move under one short
    /// lock hold; the first stored tip wins.
    pub fn offer(&self, artifact: VerifiedSnapshotArtifact) -> OfferOutcome {
        {
            let mut cell = self.inner.lock();
            if cell.demand && cell.artifact.is_none() {
                cell.artifact = Some(artifact);
                return OfferOutcome::Stored;
            }
        }
        drop(artifact);
        OfferOutcome::Skipped
    }

    /// Takes the queued artifact, clearing demand with it. Returns `None`
    /// unless an artifact is queued; demand is untouched in that case.
    pub fn take(&self) -> Option<VerifiedSnapshotArtifact> {
        let mut cell = self.inner.lock();
        if cell.artifact.is_some() {
            cell.demand = false;
            cell.artifact.take()
        } else {
            None
        }
    }
}

impl Default for SeedSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Coins observed while streaming one raw artifact pass.
struct RawStreamCounts {
    tip_hash: Hash256,
    height: u32,
    records: u64,
    outputs: u64,
}

/// Streams one raw artifact pass with the strict record parser, emitting each
/// live output through the caller's closure. Refuses empty records, which the
/// accepted path also refuses (via its record-count agreement). Duplicate
/// transaction ids cannot pair with a witness (the mint requires strict
/// acceptance), so any duplication fails the terminal length/digest binding.
fn read_raw_snapshot_stream<E, F: FnMut(&OutPoint, &[u8]) -> Result<(), E> + ?Sized>(
    reader: &mut impl Read,
    emit: &mut F,
) -> Result<RawStreamCounts, RawSeedError<E>> {
    let NativeSnapshotMetadata {
        tip_hash,
        height,
        record_count,
    } = read_snapshot_metadata_v4(reader).map_err(map_snapshot_error)?;
    let record_count_usize = usize::try_from(record_count).map_err(|_| RawSeedError::Integrity)?;

    // Untrusted counts drive the loops, but every iteration consumes bytes
    // through the capped tee: concurrently appended bytes cannot extend the
    // work past the witnessed length plus the EOF probe. Each output is
    // emitted then dropped; the only retained state is the running total,
    // and each transient output is bounded by the v4 encoding (19-byte
    // header plus a script of at most 65,535 bytes).
    let mut outputs = 0_u64;
    for _ in 0..record_count_usize {
        let (txid, output_count) = read_snapshot_record_head(reader).map_err(map_snapshot_error)?;
        if output_count == 0 {
            return Err(RawSeedError::Integrity);
        }
        for _ in 0..output_count {
            let output = read_snapshot_output(reader).map_err(map_snapshot_error)?;
            let outpoint = OutPoint::new(Txid::from(txid), output.vout);
            emit(&outpoint, &output.script_pubkey).map_err(RawSeedError::Emit)?;
            outputs = outputs.checked_add(1).ok_or(RawSeedError::Integrity)?;
        }
    }

    let mut trailer = [0_u8; MUHASH_TRAILER_LEN];
    reader.read_exact(&mut trailer).map_err(map_io_error)?;
    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => return Err(RawSeedError::Integrity),
        Err(error) => return Err(RawSeedError::Io(error)),
    }

    Ok(RawStreamCounts {
        tip_hash,
        height,
        records: record_count,
        outputs,
    })
}

/// Maps accepted-path decode failures to the seed failure taxonomy: short or
/// otherwise unreadable bytes impugn the artifact, while other transport
/// failures stay retryable.
fn map_snapshot_error<E>(error: UtxoError) -> RawSeedError<E> {
    match error {
        UtxoError::Io(error) => map_io_error(error),
        _ => RawSeedError::Integrity,
    }
}

/// A short stream is truncation (integrity); any other transport failure is `Io`.
fn map_io_error<E>(error: std::io::Error) -> RawSeedError<E> {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        RawSeedError::Integrity
    } else {
        RawSeedError::Io(error)
    }
}

/// Hashes and counts every byte read through to the strict decoder.
struct TeeReader<'a, R: Read + ?Sized> {
    inner: &'a mut R,
    hasher: Sha256,
    len: u64,
}

impl<'a, R: Read + ?Sized> TeeReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            len: 0,
        }
    }

    fn finish(self) -> ([u8; 32], u64) {
        (self.hasher.finalize().into(), self.len)
    }
}

impl<R: Read + ?Sized> Read for TeeReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.hasher.update(&buf[..read]);
        self.len = count_bytes(self.len, read)?;
        Ok(read)
    }
}
