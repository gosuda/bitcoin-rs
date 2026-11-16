use std::io::{Read, Write};

use crate::checkpoint::CheckpointReference;
use bitcoin_rs_consensus::primitives::{Hash256, Txid, varint};
use hashbrown::HashSet;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::utxo::stats::{CoinStats, CoinStatsAccumulator};
use crate::utxo::{
    UtxoError, UtxoKey, UtxoSet, UtxoSetView,
    record::{OneUtxoOut, OwnedUtxoOut, UtxoRecord},
};

const SNAPSHOT_MAGIC: u32 = 0x55_54_58_4f;
const SNAPSHOT_WRITE_VERSION: u32 = 4;
const MUHASH_TRAILER_LEN: usize = 384;
const MAX_SNAPSHOT_RECORDS: u64 = 250_000_000;
pub(crate) const WALK_CANCELLATION_INTERVAL: usize = 256;
const MAX_SNAPSHOT_COINS_PER_TXID: u32 = 1_000_000;

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

impl<O: SnapshotCoinObserver + ?Sized> SnapshotCoinObserver for &mut O {
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
        (**self).observe_coin(coin);
    }

    fn select_trailer(&mut self, fallback: [u8; MUHASH_TRAILER_LEN]) -> [u8; MUHASH_TRAILER_LEN] {
        (**self).select_trailer(fallback)
    }
}

pub struct PairObserver<A, B> {
    first: A,
    second: B,
}

impl<A, B> PairObserver<A, B> {
    #[must_use]
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }

    #[must_use]
    pub const fn stream_passes(&self) -> usize {
        1
    }

    #[must_use]
    pub fn into_parts(self) -> (A, B) {
        (self.first, self.second)
    }
}

impl<A, B> SnapshotCoinObserver for PairObserver<A, B>
where
    A: SnapshotCoinObserver,
    B: SnapshotCoinObserver,
{
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
        self.first.observe_coin(coin);
        self.second.observe_coin(coin);
    }

    fn select_trailer(&mut self, fallback: [u8; MUHASH_TRAILER_LEN]) -> [u8; MUHASH_TRAILER_LEN] {
        self.first
            .select_trailer(self.second.select_trailer(fallback))
    }
}

pub fn write_snapshot_observed<O: SnapshotCoinObserver, W: Write + ?Sized>(
    set: &UtxoSet,
    tip_hash: &Hash256,
    height: u32,
    writer: &mut W,
    observer: O,
) -> Result<([u8; MUHASH_TRAILER_LEN], O), UtxoError> {
    set.with_stable_view(|view| view.write_snapshot_observed(tip_hash, height, writer, observer))
}

impl UtxoSetView<'_> {
    pub fn write_snapshot_observed<O: SnapshotCoinObserver, W: Write + ?Sized>(
        &self,
        tip_hash: &Hash256,
        height: u32,
        writer: &mut W,
        observer: O,
    ) -> Result<([u8; MUHASH_TRAILER_LEN], O), UtxoError> {
        let (trailer, observer, _audit) =
            write_snapshot_view(self, tip_hash, height, writer, observer)?;
        Ok((trailer, observer))
    }
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
    let mut audit = WriteAudit::new(record_count);
    let declaration = V4Declaration {
        tip_hash,
        height,
        record_count,
    };
    write_v4_header(writer, &declaration)?;
    let mut snapshot_stats = view.snapshot_muhash_accumulator();
    for shard_idx in 0_u8..=u8::MAX {
        view.shard(usize::from(shard_idx)).with_table(|table| {
            for record in &table.table {
                write_record_v4(
                    writer,
                    record,
                    &mut observer,
                    &mut snapshot_stats,
                    &mut audit,
                )?;
            }
            Ok::<(), UtxoError>(())
        })?;
    }

    let fallback = snapshot_stats.map_or_else(
        || {
            view.listener_muhash3072()
                .unwrap_or([0_u8; MUHASH_TRAILER_LEN])
        },
        |stats| stats.into_stats().muhash.finalize(),
    );
    let trailer = observer.select_trailer(fallback);
    writer.write_all(&trailer)?;
    Ok((trailer, observer, audit))
}

#[derive(Clone, Copy)]
pub struct V4Declaration<'a> {
    pub tip_hash: &'a Hash256,
    pub height: u32,
    pub record_count: u64,
}

pub fn write_snapshot_records_v4<I, W>(
    records: I,
    declaration: V4Declaration<'_>,
    writer: &mut W,
    trailer: &[u8; MUHASH_TRAILER_LEN],
) -> Result<Option<V4Witness>, UtxoError>
where
    I: IntoIterator<Item = Result<UtxoRecord, UtxoError>>,
    W: Write + ?Sized,
{
    let mut tee = TeeWriter::new(writer);
    let mut audit = WriteAudit::new(declaration.record_count);
    write_v4_header(&mut tee, &declaration)?;
    let mut previous_shard: Option<u8> = None;
    for record in records {
        let record = record?;
        let shard_idx = record.txid().to_le_bytes()[0];
        if let Some(previous) = previous_shard
            && shard_idx < previous
        {
            return Err(UtxoError::SnapshotShardOutOfOrder {
                shard: shard_idx,
                previous,
            });
        }
        previous_shard = Some(shard_idx);
        write_record_v4(&mut tee, &record, &mut (), &mut None, &mut audit)?;
    }
    tee.write_all(trailer)?;
    let (sha256, len) = tee.finish();
    let complete = !audit.empty_record && audit.emitted_records == audit.declared_records;
    Ok(complete.then_some(V4Witness {
        len,
        sha256,
        tip_hash: *declaration.tip_hash,
        height: declaration.height,
        record_count: audit.declared_records,
        output_count: audit.emitted_outputs,
        origin: Origin::Encoded,
    }))
}

fn write_v4_header<W: Write + ?Sized>(
    writer: &mut W,
    declaration: &V4Declaration<'_>,
) -> Result<(), UtxoError> {
    let header = SnapshotHeader {
        magic: SNAPSHOT_MAGIC.to_le(),
        version: SNAPSHOT_WRITE_VERSION.to_le(),
        tip_hash: declaration.tip_hash.to_le_bytes(),
        height: declaration.height.to_le(),
        record_count: declaration.record_count.to_le(),
    };
    writer.write_all(header.as_bytes())?;
    Ok(())
}

fn write_record_v4<O: SnapshotCoinObserver, W: Write + ?Sized>(
    writer: &mut W,
    record: &UtxoRecord,
    observer: &mut O,
    snapshot_stats: &mut Option<CoinStatsAccumulator>,
    audit: &mut WriteAudit,
) -> Result<(), UtxoError> {
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
        shard_idx: txid.to_le_bytes()[0],
        key_prefix: record.key().to_prefix(),
        txid: txid.to_le_bytes(),
        output_count: output_count.to_le(),
    };
    writer.write_all(record_header.as_bytes())?;
    for output in record.outputs() {
        let script_len =
            u16::try_from(output.script_pubkey.len()).map_err(|_| UtxoError::ScriptTooLarge {
                len: output.script_pubkey.len(),
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
        let coin = SnapshotCoin {
            txid,
            vout: output.vout,
            value: output.value,
            script_pubkey: output.script_pubkey,
            height: output.height,
            coinbase: output.coinbase,
        };
        if let Some(stats) = snapshot_stats {
            stats.observe_coin(coin);
        }
        observer.observe_coin(coin);
    }
    Ok(())
}

impl WriteAudit {
    fn new(declared_records: u64) -> Self {
        Self {
            declared_records,
            emitted_records: 0,
            emitted_outputs: 0,
            empty_record: false,
        }
    }
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
    let record_count_usize = checked_record_count(record_count)?;

    let set = UtxoSet::new();
    let mut seen_vouts = HashSet::new();
    for _ in 0..record_count_usize {
        let (txid, outputs) = read_snapshot_record_v4(reader, &mut seen_vouts)?;
        set.insert_parsed_record(UtxoRecord::from_owned_outputs(txid, &outputs)?);
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

#[derive(Debug)]
pub struct StreamedSnapshot {
    pub tip_hash: Hash256,
    pub height: u32,
    pub record_count: u64,
    pub hash_serialized: Hash256,
    pub coin_stats: CoinStats,
}

struct ShardCoin {
    txid_le: [u8; 32],
    vout: u32,
    height: u32,
    coinbase: bool,
    value: u64,
    script_pubkey: Vec<u8>,
}

pub fn stream_snapshot_v4_records<E, F>(
    reader: &mut impl Read,
    sink: F,
) -> Result<StreamedSnapshot, E>
where
    E: From<UtxoError>,
    F: FnMut(Hash256, &UtxoRecord) -> Result<(), E>,
{
    let metadata = read_snapshot_metadata_v4(reader)?;
    stream_snapshot_v4_body(reader, metadata, sink)
}

pub fn stream_snapshot_v4_body<E, F>(
    reader: &mut impl Read,
    metadata: NativeSnapshotMetadata,
    mut sink: F,
) -> Result<StreamedSnapshot, E>
where
    E: From<UtxoError>,
    F: FnMut(Hash256, &UtxoRecord) -> Result<(), E>,
{
    let NativeSnapshotMetadata {
        tip_hash,
        height,
        record_count,
    } = metadata;
    let record_count_usize = checked_record_count(record_count)?;

    let mut seen_vouts = HashSet::new();
    let mut hasher = SerializedUtxoHasher::new();
    let mut shard_coins: Vec<ShardCoin> = Vec::new();
    let mut current_shard: Option<u8> = None;
    let mut coin_stats = CoinStatsAccumulator::with_muhash(height);
    for _ in 0..record_count_usize {
        let (shard, txid, outputs) = read_snapshot_record_v4_with_shard(reader, &mut seen_vouts)?;
        if let Some(previous) = current_shard
            && shard != previous
        {
            if shard < previous {
                return Err(UtxoError::SnapshotShardOutOfOrder { shard, previous }.into());
            }
            flush_shard(&mut hasher, &mut shard_coins, height)?;
        }
        current_shard = Some(shard);
        let txid_le = txid.to_le_bytes();
        for output in &outputs {
            coin_stats.observe_coin(SnapshotCoin {
                txid,
                vout: output.vout,
                value: output.value,
                script_pubkey: &output.script_pubkey,
                height: output.height,
                coinbase: output.coinbase,
            });
            shard_coins.push(ShardCoin {
                txid_le,
                vout: output.vout,
                height: output.height,
                coinbase: output.coinbase,
                value: output.value,
                script_pubkey: output.script_pubkey.clone(),
            });
        }
        let record = UtxoRecord::from_owned_outputs(txid, &outputs)?;
        sink(txid, &record)?;
    }
    flush_shard(&mut hasher, &mut shard_coins, height)?;

    let mut muhash_trailer = [0_u8; MUHASH_TRAILER_LEN];
    reader
        .read_exact(&mut muhash_trailer)
        .map_err(UtxoError::from)?;
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing).map_err(UtxoError::from)? != 0 {
        return Err(UtxoError::from(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snapshot has trailing bytes",
        ))
        .into());
    }

    Ok(StreamedSnapshot {
        tip_hash,
        height,
        record_count,
        hash_serialized: hasher.finish(),
        coin_stats: coin_stats.into_stats(),
    })
}

fn flush_shard(
    hasher: &mut SerializedUtxoHasher,
    shard_coins: &mut Vec<ShardCoin>,
    snapshot_height: u32,
) -> Result<(), UtxoError> {
    shard_coins.sort_unstable_by(|left, right| {
        left.txid_le
            .cmp(&right.txid_le)
            .then_with(|| left.vout.cmp(&right.vout))
    });
    for pair in shard_coins.windows(2) {
        if pair[0].txid_le == pair[1].txid_le && pair[0].vout == pair[1].vout {
            return Err(UtxoError::SnapshotDuplicateVout { vout: pair[0].vout });
        }
    }
    for coin in shard_coins.iter() {
        hasher.add(
            coin.txid_le,
            OneUtxoOut {
                vout: coin.vout,
                value: coin.value,
                script_pubkey: &coin.script_pubkey,
                coinbase: coin.coinbase,
                height: coin.height,
            },
            Some(snapshot_height),
        )?;
    }
    shard_coins.clear();
    Ok(())
}

fn read_snapshot_record_v4_with_shard(
    reader: &mut impl Read,
    seen_vouts: &mut HashSet<u32>,
) -> Result<(u8, Hash256, Vec<OwnedUtxoOut>), UtxoError> {
    let record_header_bytes =
        read_array::<{ core::mem::size_of::<SnapshotRecordHeaderV4>() }>(reader)?;
    let shard = record_header_bytes[0];
    let txid = decode_record_identity(&record_header_bytes)?;
    let output_count = read_u32(&record_header_bytes, 41);
    let outputs = read_snapshot_outputs(reader, output_count, seen_vouts)?;
    Ok((shard, txid, outputs))
}

fn checked_record_count(record_count: u64) -> Result<usize, UtxoError> {
    if record_count > MAX_SNAPSHOT_RECORDS {
        return Err(UtxoError::SnapshotRecordCountTooLarge {
            count: record_count,
        });
    }
    usize::try_from(record_count).map_err(|_| UtxoError::SnapshotRecordCountTooLarge {
        count: record_count,
    })
}

fn checked_output_count(output_count: u32) -> Result<usize, UtxoError> {
    if output_count > MAX_SNAPSHOT_COINS_PER_TXID {
        let count = usize::try_from(output_count)
            .map_err(|_| UtxoError::SnapshotOutputCountTooLarge { count: usize::MAX })?;
        return Err(UtxoError::SnapshotOutputCountTooLarge { count });
    }
    usize::try_from(output_count)
        .map_err(|_| UtxoError::SnapshotOutputCountTooLarge { count: usize::MAX })
}

fn checked_record_vout(
    output: &OwnedUtxoOut,
    seen_vouts: &mut HashSet<u32>,
) -> Result<(), UtxoError> {
    if !seen_vouts.insert(output.vout) {
        return Err(UtxoError::SnapshotDuplicateVout { vout: output.vout });
    }
    Ok(())
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
    let output_count = checked_output_count(output_count)?;
    seen_vouts.clear();
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let output = read_snapshot_output(reader)?;
        checked_record_vout(&output, seen_vouts)?;
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

/// Computes Core's `hash_serialized_3` from a consistent engine snapshot.
///
/// Coin rows must have strictly ascending full little-endian txid keys matching
/// their records. Outputs are sorted numerically within each record. Hash-owned
/// buffering retains only one decoded record and its borrowed output descriptors;
/// backend snapshot and iterator backing storage are excluded from this bound.
/// If supplied, `snapshot_height` bounds every coin's creation height.
pub fn hash_serialized_3_snapshot(
    snapshot: &dyn crate::KvSnapshot,
    snapshot_height: Option<u32>,
) -> Result<Hash256, UtxoError> {
    let mut hasher = SerializedUtxoHasher::new();
    let mut previous = None;
    for row in snapshot.iter_prefix(crate::ColumnFamily::Coins, &[])? {
        let (key, value) = row?;
        let key = crate::coins::CoinKey::from_slice(&key)?;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(crate::StorageError::InvalidOperation(
                "coin snapshot keys are not strictly ascending",
            )
            .into());
        }
        previous = Some(key);
        let record = UtxoRecord::from_encoded(value.into_boxed_slice())?;
        let txid_le = record.txid().to_le_bytes();
        if key.as_bytes() != &txid_le {
            return Err(UtxoError::CorruptRecord);
        }
        let mut outputs: Vec<_> = record.outputs().collect();
        outputs.sort_unstable_by_key(|output| output.vout);
        for output in outputs {
            hasher.add(txid_le, output, snapshot_height)?;
        }
    }
    Ok(hasher.finish())
}

pub(crate) fn hash_serialized_3_stable(view: &UtxoSetView<'_>) -> Result<Hash256, UtxoError> {
    hash_serialized_3_stable_inner(view, None, &|| false)
}

pub(crate) fn hash_serialized_3_stable_at_height(
    view: &UtxoSetView<'_>,
    snapshot_height: u32,
) -> Result<Hash256, UtxoError> {
    hash_serialized_3_stable_inner(view, Some(snapshot_height), &|| false)
}

pub(crate) fn hash_serialized_3_stable_cancellable(
    view: &UtxoSetView<'_>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Hash256, UtxoError> {
    hash_serialized_3_stable_inner(view, None, cancelled)
}

fn hash_serialized_3_stable_inner(
    view: &UtxoSetView<'_>,
    snapshot_height: Option<u32>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Hash256, UtxoError> {
    let mut engine = SerializedUtxoHasher::new();
    let mut visited = 0usize;
    for shard_idx in 0_u8..=u8::MAX {
        view.shard(usize::from(shard_idx)).with_table(|table| {
            let mut entries = Vec::with_capacity(table.output_count());
            for record in &table.table {
                for output in record.outputs() {
                    visited += 1;
                    if visited.is_multiple_of(WALK_CANCELLATION_INTERVAL) && cancelled() {
                        return Err(UtxoError::Cancelled);
                    }
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
    pub(crate) fn for_each_coin<F>(&self, f: F) -> Result<(), UtxoError>
    where
        F: FnMut(SnapshotCoin<'_>),
    {
        self.for_each_coin_cancellable(f, &|| false)
    }

    pub(crate) fn for_each_coin_cancellable<F>(
        &self,
        mut f: F,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), UtxoError>
    where
        F: FnMut(SnapshotCoin<'_>),
    {
        let mut visited = 0usize;
        for shard_idx in 0_u8..=u8::MAX {
            self.shard(usize::from(shard_idx)).with_table(|table| {
                for record in &table.table {
                    let txid = record.txid();
                    for output in record.outputs() {
                        visited += 1;
                        if visited.is_multiple_of(WALK_CANCELLATION_INTERVAL) && cancelled() {
                            return Err(UtxoError::Cancelled);
                        }
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
    witness: V4Witness,
    provenance: SeedProvenance,
}

impl VerifiedSnapshotArtifact {
    #[must_use]
    pub fn seal(witness: V4Witness, provenance: SeedProvenance) -> Self {
        Self {
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
        MAX_SNAPSHOT_COINS_PER_TXID, MAX_SNAPSHOT_RECORDS, SnapshotLoad, read_snapshot_strict_v4,
        read_snapshot_strict_v4_witnessed, write_snapshot_witnessed,
    };
    use crate::utxo::{UtxoError, UtxoKey, UtxoSet};
    use bitcoin_rs_consensus::primitives::{Amount, Hash256, TxOut, Txid};
    use std::io::Cursor;

    use crate::utxo::test_support::{TestError, TestResult};

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
        let out1 = crate::utxo::record::OwnedUtxoOut {
            vout: 0,
            value: txout(7_010)?.value.to_sat(),
            script_pubkey: txout(7_010)?.script_pubkey.to_vec(),
            coinbase: false,
            height: 100,
        };
        let out2 = crate::utxo::record::OwnedUtxoOut {
            vout: 3,
            value: 7_011,
            script_pubkey: Vec::new(),
            coinbase: true,
            height: 101,
        };
        let out3 = crate::utxo::record::OwnedUtxoOut {
            vout: 1,
            value: txout(7_012)?.value.to_sat(),
            script_pubkey: txout(7_012)?.script_pubkey.to_vec(),
            coinbase: false,
            height: 102,
        };
        let rec1 = crate::utxo::record::UtxoRecord::from_owned_outputs(first, &[out1, out2])?;
        let rec2 = crate::utxo::record::UtxoRecord::from_owned_outputs(second, &[out3])?;
        set.insert_parsed_record(rec1);
        set.insert_parsed_record(rec2);
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
        let encode_witness =
            encode_witness.ok_or(TestError::Missing("valid encode must mint a witness"))?;
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

    fn strict_stream(bytes: &mut Cursor<Vec<u8>>) -> Result<SnapshotLoad, UtxoError> {
        read_snapshot_strict_v4(bytes)
    }

    #[test]
    fn strict_loader_refuses_malformed_snapshots() -> TestResult {
        let (_, tip, height) = fixture_set()?;
        let over_records = header(tip, height, MAX_SNAPSHOT_RECORDS + 1);
        assert!(matches!(
            strict_stream(&mut Cursor::new(over_records)),
            Err(UtxoError::SnapshotRecordCountTooLarge { .. })
        ));

        let mut over_outputs = header(tip, height, 1);
        over_outputs.extend_from_slice(&record_head(txid(31), MAX_SNAPSHOT_COINS_PER_TXID + 1));
        assert!(matches!(
            strict_stream(&mut Cursor::new(over_outputs)),
            Err(UtxoError::SnapshotOutputCountTooLarge { .. })
        ));

        let repeated = txid(32);
        let mut duplicate_vout = header(tip, height, 1);
        duplicate_vout.extend_from_slice(&record_head(repeated, 2));
        duplicate_vout.extend_from_slice(&output(1, height, &[0x51])?);
        duplicate_vout.extend_from_slice(&output(1, height, &[0x51])?);
        duplicate_vout.extend_from_slice(&[0_u8; 384]);
        assert!(matches!(
            strict_stream(&mut Cursor::new(duplicate_vout)),
            Err(UtxoError::SnapshotDuplicateVout { vout: 1 })
        ));
        Ok(())
    }
}

#[cfg(test)]
mod walk_tests {
    use super::WALK_CANCELLATION_INTERVAL;
    use crate::utxo::{UtxoError, UtxoSet};
    use bitcoin_rs_consensus::primitives::Hash256;
    use std::cell::Cell;

    fn set_with_coins(count: usize) -> UtxoSet {
        let set = UtxoSet::new();
        for index in 0..count {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
            let txid = Hash256::from_le_bytes(&bytes);
            let out = crate::utxo::record::OwnedUtxoOut {
                vout: 0,
                value: 7,
                script_pubkey: vec![0x51],
                coinbase: false,
                height: 0,
            };
            let record = crate::utxo::record::UtxoRecord::from_owned_outputs(txid, &[out])
                .unwrap_or_else(|error| panic!("fixture record: {error}"));
            set.insert_parsed_record(record);
        }
        set
    }

    #[test]
    fn a_coin_walk_checks_cancellation_every_documented_interval() {
        let set = set_with_coins(2 * WALK_CANCELLATION_INTERVAL);
        let observed = Cell::new(0_usize);
        let checks = Cell::new(0_usize);

        let result = set.with_stable_view(|view| {
            view.for_each_coin_cancellable(|_| observed.set(observed.get() + 1), &|| {
                checks.set(checks.get() + 1);
                true
            })
        });

        assert!(matches!(result, Err(UtxoError::Cancelled)));
        assert_eq!(
            observed.get(),
            WALK_CANCELLATION_INTERVAL - 1,
            "the first check must run after the documented interval"
        );
        assert_eq!(checks.get(), 1, "one walk asks once before stopping");
    }
}

#[cfg(test)]
mod engine_commitment_tests {
    use super::*;
    use crate::utxo::test_support::TestResult;
    use crate::{ColumnFamily, KvIter, KvSnapshot, PrefixScan, PrefixScanLimit, StorageError};

    #[derive(Default)]
    struct Rows {
        rows: Vec<(Vec<u8>, Vec<u8>)>,
        fail_read: bool,
    }

    impl KvSnapshot for Rows {
        fn get(&self, _: ColumnFamily, _: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Err(StorageError::InvalidOperation("unused test lookup"))
        }

        fn iter_prefix<'a>(
            &'a self,
            _: ColumnFamily,
            _: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            Ok(Box::new(
                self.rows.iter().cloned().map(Ok).chain(
                    self.fail_read
                        .then_some(())
                        .into_iter()
                        .map(|()| Err(StorageError::InvalidOperation("test row read failure"))),
                ),
            ))
        }

        fn scan_prefix_from_bounded(
            &self,
            _: ColumnFamily,
            _: &[u8],
            _: &[u8],
            _: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            Err(StorageError::InvalidOperation("unused test scan"))
        }
    }

    // API-33
    #[test]
    fn engine_commitment_matches_independent_stable_view_ordering() -> TestResult {
        let set = UtxoSet::new();
        let mut snapshot = Rows::default();
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[7; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);
        for (first, suffix) in [(255, 0), (1, 255), (0, 9), (1, 0), (0, 2)] {
            let mut key = [0_u8; 32];
            key[0] = first;
            key[31] = suffix;
            let outputs = [300, 1, 256, 0].map(|vout| OwnedUtxoOut {
                vout,
                value: u64::from(vout) + 1,
                script_pubkey: if vout == 1 {
                    p2pkh.clone()
                } else {
                    vec![0x51, 0x75]
                },
                coinbase: vout == 0,
                height: 10,
            });
            let record = UtxoRecord::from_owned_outputs(Hash256::from_le_bytes(&key), &outputs)?;
            snapshot.rows.push((key.to_vec(), record.bytes().to_vec()));
            set.insert_parsed_record(record);
        }
        snapshot
            .rows
            .sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let expected = set.lock_stable_view().hash_serialized_3()?;
        assert_eq!(hash_serialized_3_snapshot(&snapshot, None)?, expected);
        assert_eq!(hash_serialized_3_snapshot(&snapshot, Some(10))?, expected);
        assert!(matches!(
            hash_serialized_3_snapshot(&snapshot, Some(9)),
            Err(UtxoError::SnapshotCoinHeightOutOfRange {
                height: 10,
                snapshot_height: 9
            })
        ));

        snapshot.rows.swap(0, 1);
        assert!(matches!(
            hash_serialized_3_snapshot(&snapshot, None),
            Err(UtxoError::Storage(StorageError::InvalidOperation(_)))
        ));
        snapshot.rows.swap(0, 1);
        snapshot.rows[0].0[31] ^= 1;
        assert!(matches!(
            hash_serialized_3_snapshot(&snapshot, None),
            Err(UtxoError::CorruptRecord)
        ));
        snapshot.rows[0].0.pop();
        assert!(matches!(
            hash_serialized_3_snapshot(&snapshot, None),
            Err(UtxoError::Storage(StorageError::InvalidOperation(_)))
        ));
        snapshot.rows[0].0.push(9);
        snapshot.rows[0].1.clear();
        assert!(matches!(
            hash_serialized_3_snapshot(&snapshot, None),
            Err(UtxoError::CorruptRecord)
        ));
        snapshot.rows.clear();
        snapshot.fail_read = true;
        assert!(matches!(
            hash_serialized_3_snapshot(&snapshot, None),
            Err(UtxoError::Storage(StorageError::InvalidOperation(
                "test row read failure"
            )))
        ));
        Ok(())
    }
}
