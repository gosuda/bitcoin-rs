use std::io::{BufReader, Read, Seek, Write};

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
const SEED_READ_BUFFER_BYTES: usize = 64 * 1024;

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

pub struct SnapshotLoad {
    pub set: UtxoSet,
    pub tip_hash: Hash256,
    pub height: u32,
    pub muhash_trailer: [u8; MUHASH_TRAILER_LEN],
}

#[derive(Copy, Clone)]
pub struct SnapshotCoin<'a> {
    pub txid: Hash256,
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: &'a [u8],
    pub height: u32,
    pub coinbase: bool,
}

pub trait SnapshotCoinObserver {
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>);

    fn select_trailer(&mut self, fallback: [u8; MUHASH_TRAILER_LEN]) -> [u8; MUHASH_TRAILER_LEN] {
        fallback
    }
}

impl SnapshotCoinObserver for () {
    fn observe_coin(&mut self, _: SnapshotCoin<'_>) {}
}

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

struct WriteAudit {
    declared_records: u64,
    emitted_records: u64,
    emitted_outputs: u64,
    empty_record: bool,
}

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

fn count_bytes(len: u64, transfer: usize) -> std::io::Result<u64> {
    let count = u64::try_from(transfer)
        .map_err(|_| std::io::Error::other("snapshot byte count overflow"))?;
    len.checked_add(count)
        .ok_or_else(|| std::io::Error::other("snapshot byte count overflow"))
}

/// Parsed native-v4 header identity; this does not validate the coin body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeSnapshotMetadata {
    pub tip_hash: Hash256,
    pub height: u32,
    /// Declared transaction-level records, not output count.
    pub record_count: u64,
}

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

pub fn read_snapshot_strict_v4(reader: &mut impl Read) -> Result<SnapshotLoad, UtxoError> {
    read_snapshot_strict_v4_observed(reader, ()).map(|(snapshot, ())| snapshot)
}

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

pub(crate) fn hash_serialized_3_stable(view: &UtxoSetView<'_>) -> Result<Hash256, UtxoError> {
    hash_serialized_3_stable_inner(view, None)
}

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

/// Proof that exactly these bytes passed strict v4 decode. Only `utxo` mints.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    Decoded,
    Encoded,
}

impl V4Witness {
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.len
    }

    #[must_use]
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    #[must_use]
    pub fn tip_hash(&self) -> Hash256 {
        self.tip_hash
    }

    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    #[must_use]
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    #[must_use]
    pub fn output_count(&self) -> u64 {
        self.output_count
    }

    #[must_use]
    pub fn is_decoded(&self) -> bool {
        self.origin == Origin::Decoded
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedProvenance {
    Checkpoint(CheckpointReference),
    AssumeUtxoArchive { base: [u8; 32] },
}

#[derive(Debug, Error)]
pub enum RawSeedError<E> {
    #[error("seed artifact bytes do not match the witness")]
    Integrity,
    #[error("seed artifact read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("seed emit failed: {0}")]
    Emit(E),
    #[error("seed traversal cancelled")]
    Cancelled,
}

pub struct VerifiedSnapshotArtifact {
    file: std::fs::File,
    witness: V4Witness,
    provenance: SeedProvenance,
}

impl VerifiedSnapshotArtifact {
    #[must_use]
    pub fn seal(file: std::fs::File, witness: V4Witness, provenance: SeedProvenance) -> Self {
        Self {
            file,
            witness,
            provenance,
        }
    }

    #[must_use]
    pub fn tip(&self) -> (u32, Hash256) {
        (self.witness.height, self.witness.tip_hash)
    }

    #[must_use]
    pub fn provenance(&self) -> SeedProvenance {
        self.provenance
    }

    /// `cancelled` is polled at entry and every 4,096 emitted coins; a trip
    /// returns [`RawSeedError::Cancelled`] with the bundle intact so the
    /// caller can retry with the same artifact.
    pub fn for_each_coin_raw<E, F: FnMut(&OutPoint, &[u8]) -> Result<(), E> + ?Sized>(
        &mut self,
        emit: &mut F,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), RawSeedError<E>> {
        self.file.rewind().map_err(RawSeedError::Io)?;
        let limit = self
            .witness
            .byte_len()
            .checked_add(1)
            .ok_or(RawSeedError::Integrity)?;
        let capped = Read::by_ref(&mut self.file).take(limit);
        let mut buffered = BufReader::with_capacity(SEED_READ_BUFFER_BYTES, capped);
        let mut tee = TeeReader::new(&mut buffered);
        let stream = read_raw_snapshot_stream(&mut tee, emit, cancelled)?;
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

pub type SeedOfferCell = std::sync::Arc<SeedSlot>;

pub struct SeedSlot {
    inner: Mutex<SeedCell>,
}

struct SeedCell {
    demand: bool,
    artifact: Option<VerifiedSnapshotArtifact>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferOutcome {
    Stored,
    Skipped,
}

impl SeedSlot {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SeedCell {
                demand: false,
                artifact: None,
            }),
        }
    }

    #[must_use]
    pub fn is_wanted(&self) -> bool {
        let cell = self.inner.lock();
        cell.demand && cell.artifact.is_none()
    }

    pub fn want(&self) {
        let mut cell = self.inner.lock();
        if !cell.demand && cell.artifact.is_none() {
            cell.demand = true;
        }
    }

    pub fn rest(&self) {
        let dropped = {
            let mut cell = self.inner.lock();
            cell.demand = false;
            cell.artifact.take()
        };
        drop(dropped);
    }

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

struct RawStreamCounts {
    tip_hash: Hash256,
    height: u32,
    records: u64,
    outputs: u64,
}

fn read_raw_snapshot_stream<E, F: FnMut(&OutPoint, &[u8]) -> Result<(), E> + ?Sized>(
    reader: &mut impl Read,
    emit: &mut F,
    cancelled: &dyn Fn() -> bool,
) -> Result<RawStreamCounts, RawSeedError<E>> {
    const SEED_CANCEL_POLL_COINS: u64 = 4_096;
    if cancelled() {
        return Err(RawSeedError::Cancelled);
    }
    let NativeSnapshotMetadata {
        tip_hash,
        height,
        record_count,
    } = read_snapshot_metadata_v4(reader).map_err(map_snapshot_error)?;
    let record_count_usize = usize::try_from(record_count).map_err(|_| RawSeedError::Integrity)?;

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
            if outputs.is_multiple_of(SEED_CANCEL_POLL_COINS) && cancelled() {
                return Err(RawSeedError::Cancelled);
            }
        }
    }
    if cancelled() {
        return Err(RawSeedError::Cancelled);
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

fn map_snapshot_error<E>(error: UtxoError) -> RawSeedError<E> {
    match error {
        UtxoError::Io(error) => map_io_error(error),
        _ => RawSeedError::Integrity,
    }
}

fn map_io_error<E>(error: std::io::Error) -> RawSeedError<E> {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        RawSeedError::Integrity
    } else {
        RawSeedError::Io(error)
    }
}

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

#[cfg(test)]
mod seed_no_token_tests {
    use super::{
        read_snapshot_strict_v4, read_snapshot_strict_v4_witnessed, write_snapshot_witnessed,
    };
    use crate::{
        UtxoError, UtxoKey, UtxoSet,
        contract::{BlockChanges, UtxoAdd, commit_block_changes},
    };
    use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, Script, TxOut, Txid};
    use std::io::Cursor;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn txid(seed: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
        bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
        bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    fn txout(seed: u64) -> TestResult<TxOut> {
        Ok(TxOut {
            value: Amount::from_sat(2_000 + seed),
            script_pubkey: vec![0x51, u8::try_from(seed % 256)?].into(),
        })
    }

    fn fixture_set() -> TestResult<(UtxoSet, Hash256, u32)> {
        let set = UtxoSet::new();
        let first = txid(7_001);
        let second = txid(7_002);
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(first.into(), 0),
            txout(7_010)?,
            false,
            100,
        ));
        changes.add(UtxoAdd::new(
            OutPoint::new(first.into(), 3),
            TxOut {
                value: Amount::from_sat(7_011),
                script_pubkey: Script::new(),
            },
            true,
            101,
        ));
        changes.add(UtxoAdd::new(
            OutPoint::new(second.into(), 1),
            txout(7_012)?,
            false,
            102,
        ));
        commit_block_changes(&set, &changes, &txid(7_003))?;
        Ok((set, txid(7_004), 103))
    }

    fn header(tip: Hash256, height: u32, record_count: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(52);
        bytes.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&tip.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&record_count.to_le_bytes());
        bytes
    }

    fn record_head(record_txid: Hash256, output_count: u32) -> Vec<u8> {
        let key = UtxoKey::from_txid(&Txid::from(record_txid));
        let mut bytes = Vec::with_capacity(45);
        bytes.push(key.shard());
        bytes.extend_from_slice(&key.to_prefix());
        bytes.extend_from_slice(&record_txid.to_le_bytes());
        bytes.extend_from_slice(&output_count.to_le_bytes());
        bytes
    }

    fn output(vout: u32, height: u32, script: &[u8]) -> TestResult<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&vout.to_le_bytes());
        bytes.extend_from_slice(&1_000_u64.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&u16::try_from(script.len())?.to_le_bytes());
        bytes.extend_from_slice(script);
        Ok(bytes)
    }

    #[test]
    fn seed_no_token_from_bad_bytes_and_no_foreign_mint() -> TestResult {
        let (set, tip, height) = fixture_set()?;
        let mut good = Vec::new();
        let (_, (), encode_witness) = write_snapshot_witnessed(&set, &tip, height, &mut good, ())?;
        let encode_witness = encode_witness.ok_or("valid encode must mint a witness")?;
        assert_eq!(encode_witness.byte_len(), u64::try_from(good.len())?);
        assert_eq!(encode_witness.record_count(), 2);
        assert_eq!(encode_witness.output_count(), 3);
        assert!(!encode_witness.is_decoded(), "encode must not claim decode");
        let (load, (), decode_witness) =
            read_snapshot_strict_v4_witnessed(&mut Cursor::new(good), ())?;
        assert_eq!((load.tip_hash, load.height), (tip, height));
        assert!(decode_witness.is_decoded(), "decode must claim decode");
        assert_eq!(decode_witness.sha256(), encode_witness.sha256());
        assert_eq!(decode_witness.byte_len(), encode_witness.byte_len());

        let duplicate = txid(11);
        let mut duplicate_bytes = header(tip, height, 2);
        for vout in [0_u32, 1] {
            duplicate_bytes.extend_from_slice(&record_head(duplicate, 1));
            duplicate_bytes.extend_from_slice(&output(vout, height, &[0x51])?);
        }
        duplicate_bytes.extend_from_slice(&[0_u8; 384]);
        assert!(matches!(
            read_snapshot_strict_v4(&mut Cursor::new(duplicate_bytes.clone())),
            Err(UtxoError::SnapshotRecordCountMismatch {
                declared: 2,
                actual: 1
            })
        ));
        assert!(matches!(
            read_snapshot_strict_v4_witnessed(&mut Cursor::new(duplicate_bytes), ()),
            Err(UtxoError::SnapshotRecordCountMismatch {
                declared: 2,
                actual: 1
            })
        ));

        let empty = txid(22);
        let mut empty_bytes = header(tip, height, 1);
        empty_bytes.extend_from_slice(&record_head(empty, 0));
        empty_bytes.extend_from_slice(&[0_u8; 384]);
        assert!(matches!(
            read_snapshot_strict_v4(&mut Cursor::new(empty_bytes.clone())),
            Err(UtxoError::SnapshotRecordCountMismatch {
                declared: 1,
                actual: 0
            })
        ));
        assert!(matches!(
            read_snapshot_strict_v4_witnessed(&mut Cursor::new(empty_bytes), ()),
            Err(UtxoError::SnapshotRecordCountMismatch {
                declared: 1,
                actual: 0
            })
        ));
        Ok(())
    }
}
