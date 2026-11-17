use std::io::{self, Read, Write};

use bitcoin_rs_consensus::primitives::{AssumeUtxoData, Hash256, Network, varint};
use thiserror::Error;

use crate::utxo::{
    UtxoError, UtxoSet, UtxoSetView,
    record::{OneUtxoOut, OwnedUtxoOut, UtxoRecord},
    shard::ShardTable,
    snapshot::{SerializedUtxoHasher, SnapshotCoin, SnapshotCoinObserver},
    stats::{CoinStats, CoinStatsAccumulator, scan_coin_stats},
};

const MAGIC: [u8; 5] = *b"utxo\xff";
const VERSION: u16 = 2;
const HEADER_BYTES: u64 = 51;
const MAX_SCRIPT_BYTES: u64 = 10_000;
const MAX_COMPACT_SIZE: u64 = 0x0200_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotMetadata {
    pub version: u16,
    pub network_magic: [u8; 4],
    pub base_block_hash: Hash256,
    pub coins_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotLimits {
    pub max_file_bytes: u64,
    pub max_coins: u64,
    pub max_script_bytes: u64,
    pub max_coins_per_txid: u32,
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 32 * 1024 * 1024 * 1024,
            max_coins: 250_000_000,
            max_script_bytes: 32 * 1024 * 1024 * 1024,
            max_coins_per_txid: 1_000_000,
        }
    }
}

pub struct CoreSnapshot {
    pub set: UtxoSet,
    pub metadata: SnapshotMetadata,
    pub anchor: &'static AssumeUtxoData,
    pub hash_serialized: Hash256,
    pub bytes_read: u64,
}

/// One owned UTXO set sealed with the commitment and statistics that were
/// derived from exactly its coins.
///
/// `&UtxoSet` would let a holder invalidate the proof. The only way out is
/// [`Self::into_parts`], which consumes the proof together with the set.
pub struct VerifiedSnapshotState {
    set: UtxoSet,
    base_hash: Hash256,
    height: u32,
    hash_serialized: Hash256,
    stats: CoinStats,
}

#[derive(Debug, Error)]
pub enum StateVerifyError {
    #[error("snapshot UTXO state: {0}")]
    Utxo(#[from] UtxoError),
    #[error("snapshot commitment {actual} does not match pinned {expected}")]
    CommitmentMismatch { expected: Hash256, actual: Hash256 },
}

impl VerifiedSnapshotState {
    pub fn verify(set: UtxoSet, anchor: &AssumeUtxoData) -> Result<Self, StateVerifyError> {
        let (actual, stats) = set.with_stable_view(|view| {
            let actual = view.hash_serialized_3_at_height(anchor.height)?;
            let stats = if actual == anchor.hash_serialized {
                Some(scan_coin_stats(view, anchor.height, true)?)
            } else {
                None
            };
            Ok::<_, UtxoError>((actual, stats))
        })?;
        let Some(stats) = stats else {
            return Err(StateVerifyError::CommitmentMismatch {
                expected: anchor.hash_serialized,
                actual,
            });
        };
        Ok(Self {
            set,
            base_hash: anchor.block_hash,
            height: anchor.height,
            hash_serialized: actual,
            stats,
        })
    }

    #[must_use]
    pub const fn base_hash(&self) -> Hash256 {
        self.base_hash
    }

    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    #[must_use]
    pub const fn hash_serialized(&self) -> Hash256 {
        self.hash_serialized
    }

    #[must_use]
    pub const fn stats(&self) -> &CoinStats {
        &self.stats
    }

    #[must_use]
    pub fn into_parts(self) -> (UtxoSet, CoinStats) {
        (self.set, self.stats)
    }
}

pub struct VerifiedCoreSnapshot {
    pub metadata: SnapshotMetadata,
    pub anchor: &'static AssumeUtxoData,
    pub bytes_read: u64,
    state: VerifiedSnapshotState,
}

impl VerifiedCoreSnapshot {
    #[must_use]
    pub const fn state(&self) -> &VerifiedSnapshotState {
        &self.state
    }

    #[must_use]
    pub fn into_state(self) -> VerifiedSnapshotState {
        self.state
    }
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("snapshot truncated at byte {offset}")]
    Truncated { offset: u64 },
    #[error("snapshot input failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid Bitcoin Core snapshot magic")]
    InvalidMagic,
    #[error("unsupported Bitcoin Core snapshot version {version}")]
    UnsupportedVersion { version: u16 },
    #[error("snapshot network magic {actual:02x?} does not match {expected:02x?}")]
    WrongNetwork { expected: [u8; 4], actual: [u8; 4] },
    #[error("snapshot base {base_hash} is not pinned for {network:?}")]
    UnsupportedAnchor {
        network: Network,
        base_hash: Hash256,
    },
    #[error("snapshot {resource} budget exceeded: {actual} > {limit}")]
    LimitExceeded {
        resource: &'static str,
        actual: u64,
        limit: u64,
    },
    #[error("snapshot CompactSize is noncanonical")]
    NonCanonicalCompactSize,
    #[error("snapshot CompactSize value {value} exceeds the Core limit")]
    CompactSizeTooLarge { value: u64 },
    #[error("snapshot Core VARINT overflows its field")]
    VarIntOverflow,
    #[error("snapshot contains an empty transaction group")]
    EmptyGroup,
    #[error("snapshot group declares {group} coins with only {remaining} remaining")]
    CoinCountMismatch { group: u64, remaining: u64 },
    #[error("snapshot declared {declared} coins, wrote {actual}")]
    DeclaredCoinCountMismatch { declared: u64, actual: u64 },
    #[error("snapshot operation interrupted")]
    Interrupted,
    #[error("snapshot transaction groups are duplicated or out of Core byte order")]
    TransactionOrder,
    #[error("snapshot repeats output index {vout}")]
    DuplicateOutpoint { vout: u32 },
    #[error("snapshot output index {vout} is invalid")]
    InvalidOutpoint { vout: u64 },
    #[error("snapshot coin height {height} exceeds base height {base_height}")]
    InvalidHeight { height: u32, base_height: u32 },
    #[error("snapshot compressed amount {compressed} is out of range")]
    InvalidAmount { compressed: u64 },
    #[error("snapshot script length {length} exceeds 10000 bytes")]
    InvalidScriptLength { length: u64 },
    #[error("snapshot uncompressed P2PK encoding has an invalid curve point")]
    InvalidPublicKey,
    #[error("snapshot has trailing bytes")]
    TrailingBytes,
    #[error("snapshot UTXO state: {0}")]
    Utxo(#[from] UtxoError),
    #[error("snapshot commitment {actual} does not match pinned {expected}")]
    CommitmentMismatch { expected: Hash256, actual: Hash256 },
}

pub fn read_metadata(reader: &mut impl Read) -> Result<SnapshotMetadata, SnapshotError> {
    Decoder::new(reader, HEADER_BYTES).metadata()
}

pub fn read_and_verify(
    reader: &mut impl Read,
    network: Network,
    limits: SnapshotLimits,
) -> Result<CoreSnapshot, SnapshotError> {
    let authenticated = authenticate(reader, network, limits)?;
    let set = UtxoSet::new();
    for record in authenticated.records {
        set.insert_parsed_record(record);
    }
    Ok(CoreSnapshot {
        set,
        metadata: authenticated.metadata,
        anchor: authenticated.anchor,
        hash_serialized: authenticated.hash_serialized,
        bytes_read: authenticated.bytes_read,
    })
}

pub fn read_verified(
    reader: &mut impl Read,
    network: Network,
    limits: SnapshotLimits,
) -> Result<VerifiedCoreSnapshot, SnapshotError> {
    read_verified_observed(reader, network, limits, ()).map(|(snapshot, ())| snapshot)
}

pub fn read_verified_observed<O: SnapshotCoinObserver>(
    reader: &mut impl Read,
    network: Network,
    limits: SnapshotLimits,
    mut observer: O,
) -> Result<(VerifiedCoreSnapshot, O), SnapshotError> {
    let authenticated = authenticate(reader, network, limits)?;
    let anchor = authenticated.anchor;
    let mut accumulator = CoinStatsAccumulator::with_parallel_muhash(anchor.height);
    let set = UtxoSet::new();
    for record in authenticated.records {
        let txid = record.txid();
        for output in record.outputs() {
            let coin = SnapshotCoin {
                txid,
                vout: output.vout,
                value: output.value,
                script_pubkey: output.script_pubkey,
                height: output.height,
                coinbase: output.coinbase,
            };
            accumulator.observe_coin(coin);
            observer.observe_coin(coin);
        }
        set.insert_parsed_record(record);
    }
    Ok((
        VerifiedCoreSnapshot {
            metadata: authenticated.metadata,
            anchor,
            bytes_read: authenticated.bytes_read,
            state: VerifiedSnapshotState {
                set,
                base_hash: anchor.block_hash,
                height: anchor.height,
                hash_serialized: authenticated.hash_serialized,
                stats: accumulator.into_stats(),
            },
        },
        observer,
    ))
}

pub struct CoreSnapshotStream<'a, R> {
    decoder: Decoder<'a, R>,
    metadata: SnapshotMetadata,
    anchor: &'static AssumeUtxoData,
}

pub struct StreamedCoreSnapshot {
    pub bytes_read: u64,
    pub coin_stats: CoinStats,
}

impl<'a, R: Read> CoreSnapshotStream<'a, R> {
    pub fn open(reader: &'a mut R, network: Network) -> Result<Self, SnapshotError> {
        let mut decoder = Decoder::new(reader, SnapshotLimits::default().max_file_bytes);
        let metadata = decoder.metadata()?;
        let anchor = anchor_for(&metadata, network)?;
        Ok(Self {
            decoder,
            metadata,
            anchor,
        })
    }

    #[must_use]
    pub const fn metadata(&self) -> &SnapshotMetadata {
        &self.metadata
    }

    #[must_use]
    pub const fn anchor(&self) -> &'static AssumeUtxoData {
        self.anchor
    }

    pub fn stream<E>(
        mut self,
        mut sink: impl FnMut(Hash256, &UtxoRecord) -> Result<(), E>,
    ) -> Result<StreamedCoreSnapshot, E>
    where
        E: From<SnapshotError>,
    {
        let anchor = self.anchor;
        let mut accumulator = CoinStatsAccumulator::with_parallel_muhash(anchor.height);
        let mut sink_error: Option<E> = None;
        let coins = self.decoder.coins_into(
            self.metadata.coins_count,
            anchor.height,
            SnapshotLimits::default(),
            |txid, record| {
                for output in record.outputs() {
                    accumulator.observe_coin(SnapshotCoin {
                        txid,
                        vout: output.vout,
                        value: output.value,
                        script_pubkey: output.script_pubkey,
                        height: output.height,
                        coinbase: output.coinbase,
                    });
                }
                sink(txid, &record).map_err(|error| {
                    sink_error = Some(error);
                    SnapshotError::Interrupted
                })
            },
        );
        let hash_serialized = match coins {
            Ok(hash) => hash,
            Err(error) => return Err(sink_error.unwrap_or_else(|| error.into())),
        };
        self.decoder.end()?;
        if hash_serialized != anchor.hash_serialized {
            return Err(SnapshotError::CommitmentMismatch {
                expected: anchor.hash_serialized,
                actual: hash_serialized,
            }
            .into());
        }
        Ok(StreamedCoreSnapshot {
            bytes_read: self.decoder.consumed,
            coin_stats: accumulator.into_stats(),
        })
    }
}

struct Authenticated {
    records: Vec<UtxoRecord>,
    metadata: SnapshotMetadata,
    anchor: &'static AssumeUtxoData,
    hash_serialized: Hash256,
    bytes_read: u64,
}

fn anchor_for(
    metadata: &SnapshotMetadata,
    network: Network,
) -> Result<&'static AssumeUtxoData, SnapshotError> {
    if metadata.network_magic != network.magic() {
        return Err(SnapshotError::WrongNetwork {
            expected: network.magic(),
            actual: metadata.network_magic,
        });
    }
    network
        .assume_utxo_for_hash(metadata.base_block_hash)
        .ok_or(SnapshotError::UnsupportedAnchor {
            network,
            base_hash: metadata.base_block_hash,
        })
}

fn authenticate(
    reader: &mut impl Read,
    network: Network,
    limits: SnapshotLimits,
) -> Result<Authenticated, SnapshotError> {
    let mut decoder = Decoder::new(reader, limits.max_file_bytes);
    let metadata = decoder.metadata()?;
    let anchor = anchor_for(&metadata, network)?;
    let mut records = Vec::new();
    let hash_serialized =
        decoder.coins_into(metadata.coins_count, anchor.height, limits, |_, record| {
            records.push(record);
            Ok(())
        })?;
    decoder.end()?;
    if hash_serialized != anchor.hash_serialized {
        return Err(SnapshotError::CommitmentMismatch {
            expected: anchor.hash_serialized,
            actual: hash_serialized,
        });
    }
    Ok(Authenticated {
        records,
        metadata,
        anchor,
        hash_serialized,
        bytes_read: decoder.consumed,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreV2WriteReport {
    pub bytes: u64,
    pub coins: u64,
    pub txoutset_hash: Hash256,
}

/// Polls `should_stop()` every 5,000 coins and immediately aborts with
/// [`SnapshotError::Interrupted`].
///
/// Fails with [`SnapshotError::DeclaredCoinCountMismatch`] if the written coins count
/// does not match `coins_count`.
pub fn write_core_v2<W: Write + ?Sized>(
    view: &UtxoSetView<'_>,
    base: &CoreV2Base,
    writer: &mut W,
    should_stop: &dyn Fn() -> bool,
) -> Result<CoreV2WriteReport, SnapshotError> {
    if should_stop() {
        return Err(SnapshotError::Interrupted);
    }
    write_v2_header(writer, base)?;
    let mut encoder = CoreV2Encoder {
        writer,
        base_height: base.base_height,
        coins_count: base.coins_count,
        coins_written: 0,
        last_polled_coins: 0,
        total_bytes: HEADER_BYTES,
        commitment: SerializedUtxoHasher::new(),
        varint_buf: Vec::with_capacity(10),
        should_stop,
    };
    for shard_idx in 0_u8..=u8::MAX {
        let shard = view.shard(usize::from(shard_idx));
        shard.with_table(|table| encoder.write_table(table))?;
    }
    encoder.finish()
}

pub struct CoreV2Base {
    pub network: Network,
    pub base_hash: Hash256,
    pub base_height: u32,
    pub coins_count: u64,
}

fn write_v2_header<W: Write + ?Sized>(
    writer: &mut W,
    base: &CoreV2Base,
) -> Result<(), SnapshotError> {
    writer.write_all(&MAGIC)?;
    writer.write_all(&VERSION.to_le_bytes())?;
    writer.write_all(&base.network.magic())?;
    writer.write_all(&base.base_hash.to_le_bytes())?;
    writer.write_all(&base.coins_count.to_le_bytes())?;
    Ok(())
}

struct CoreV2Encoder<'w, W: Write + ?Sized> {
    writer: &'w mut W,
    base_height: u32,
    coins_count: u64,
    coins_written: u64,
    last_polled_coins: u64,
    total_bytes: u64,
    commitment: SerializedUtxoHasher,
    varint_buf: Vec<u8>,
    should_stop: &'w dyn Fn() -> bool,
}

impl<W: Write + ?Sized> CoreV2Encoder<'_, W> {
    fn write_table(&mut self, table: &ShardTable) -> Result<(), SnapshotError> {
        let mut records: Vec<&UtxoRecord> = table.table.iter().collect();
        records.sort_unstable_by(|left, right| {
            left.txid().to_le_bytes().cmp(&right.txid().to_le_bytes())
        });
        for record in records {
            self.write_record(record)?;
        }
        Ok(())
    }

    fn write_record(&mut self, record: &UtxoRecord) -> Result<(), SnapshotError> {
        let txid_bytes = record.txid().to_le_bytes();
        let mut outputs: Vec<OneUtxoOut<'_>> = record.outputs().collect();
        if outputs.is_empty() {
            return Ok(());
        }
        outputs.sort_unstable_by(|left, right| {
            crate::utxo::compress::cmp_core_varint_key(left.vout, right.vout)
        });
        let mut commitment_outputs: Vec<_> = record.outputs().collect();
        commitment_outputs.sort_unstable_by_key(|output| output.vout);

        let group_count =
            u64::try_from(outputs.len()).map_err(|_| SnapshotError::LimitExceeded {
                resource: "coins per txid",
                actual: u64::MAX,
                limit: u64::from(u32::MAX),
            })?;

        self.write_counted(&txid_bytes)?;
        let group_encoded = varint::encode(group_count);
        self.write_counted(group_encoded.as_slice())?;
        for output in outputs {
            let entry_bytes =
                write_output_entry(self.writer, &output, self.base_height, &mut self.varint_buf)?;
            self.add_bytes(entry_bytes)?;
            self.count_coin()?;
        }
        for output in commitment_outputs {
            self.commitment
                .add(txid_bytes, output, Some(self.base_height))?;
        }
        Ok(())
    }

    fn write_counted(&mut self, bytes: &[u8]) -> Result<(), SnapshotError> {
        self.writer.write_all(bytes)?;
        self.add_bytes(u64::try_from(bytes.len()).unwrap_or(0))
    }

    fn add_bytes(&mut self, extra: u64) -> Result<(), SnapshotError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(extra)
            .ok_or(SnapshotError::VarIntOverflow)?;
        Ok(())
    }

    fn count_coin(&mut self) -> Result<(), SnapshotError> {
        self.coins_written = self
            .coins_written
            .checked_add(1)
            .ok_or(SnapshotError::VarIntOverflow)?;
        if self.coins_written > self.coins_count {
            return Err(SnapshotError::DeclaredCoinCountMismatch {
                declared: self.coins_count,
                actual: self.coins_written,
            });
        }
        if self.coins_written.saturating_sub(self.last_polled_coins) >= 5000 {
            self.last_polled_coins = self.coins_written;
            if (self.should_stop)() {
                return Err(SnapshotError::Interrupted);
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<CoreV2WriteReport, SnapshotError> {
        if self.coins_written != self.coins_count {
            return Err(SnapshotError::DeclaredCoinCountMismatch {
                declared: self.coins_count,
                actual: self.coins_written,
            });
        }
        Ok(CoreV2WriteReport {
            bytes: self.total_bytes,
            coins: self.coins_written,
            txoutset_hash: self.commitment.finish(),
        })
    }
}

fn write_output_entry<W: Write + ?Sized>(
    writer: &mut W,
    output: &OneUtxoOut<'_>,
    base_height: u32,
    varint_buf: &mut Vec<u8>,
) -> Result<u64, SnapshotError> {
    let code = entry_code(output, base_height)?;
    let mut written = 0_u64;
    written = add_written(written, write_vout_entry(writer, output.vout)?)?;
    written = add_written(
        written,
        write_core_varint_entry(writer, u64::from(code), varint_buf)?,
    )?;
    let compressed_amount = crate::utxo::compress::compress_amount(output.value)?;
    written = add_written(
        written,
        write_core_varint_entry(writer, compressed_amount, varint_buf)?,
    )?;
    written = add_written(
        written,
        write_script_entry(writer, output.script_pubkey, varint_buf)?,
    )?;
    Ok(written)
}

fn entry_code(output: &OneUtxoOut<'_>, base_height: u32) -> Result<u32, SnapshotError> {
    if output.vout == u32::MAX {
        return Err(SnapshotError::InvalidOutpoint {
            vout: u64::from(output.vout),
        });
    }
    if output.height > base_height {
        return Err(SnapshotError::InvalidHeight {
            height: output.height,
            base_height,
        });
    }
    let raw_code = (u64::from(output.height) << 1) | u64::from(output.coinbase);
    u32::try_from(raw_code).map_err(|_| SnapshotError::VarIntOverflow)
}

fn write_vout_entry<W: Write + ?Sized>(writer: &mut W, vout: u32) -> Result<u64, SnapshotError> {
    let encoded = varint::encode(u64::from(vout));
    writer.write_all(encoded.as_slice())?;
    Ok(counted(encoded.len()))
}

fn write_core_varint_entry<W: Write + ?Sized>(
    writer: &mut W,
    value: u64,
    varint_buf: &mut Vec<u8>,
) -> Result<u64, SnapshotError> {
    varint_buf.clear();
    crate::utxo::compress::write_core_varint(value, varint_buf);
    writer.write_all(varint_buf)?;
    Ok(counted(varint_buf.len()))
}

fn write_script_entry<W: Write + ?Sized>(
    writer: &mut W,
    script: &[u8],
    varint_buf: &mut Vec<u8>,
) -> Result<u64, SnapshotError> {
    let Some((script_code, payload)) = crate::utxo::compress::compress_script(script) else {
        return write_raw_script_entry(writer, script, varint_buf);
    };
    let mut written = write_core_varint_entry(writer, script_code, varint_buf)?;
    writer.write_all(payload)?;
    written = written
        .checked_add(counted(payload.len()))
        .ok_or(SnapshotError::VarIntOverflow)?;
    Ok(written)
}

fn write_raw_script_entry<W: Write + ?Sized>(
    writer: &mut W,
    script: &[u8],
    varint_buf: &mut Vec<u8>,
) -> Result<u64, SnapshotError> {
    let script_len = script.len();
    if script_len > 10_000 {
        return Err(SnapshotError::InvalidScriptLength {
            length: u64::try_from(script_len).unwrap_or(u64::MAX),
        });
    }
    let script_code = u64::try_from(script_len)
        .map_err(|_| SnapshotError::VarIntOverflow)?
        .checked_add(6)
        .ok_or(SnapshotError::VarIntOverflow)?;
    let mut written = write_core_varint_entry(writer, script_code, varint_buf)?;
    writer.write_all(script)?;
    written = written
        .checked_add(counted(script.len()))
        .ok_or(SnapshotError::VarIntOverflow)?;
    Ok(written)
}

fn counted(extra: usize) -> u64 {
    u64::try_from(extra).unwrap_or(0)
}

fn add_written(total: u64, extra: u64) -> Result<u64, SnapshotError> {
    total
        .checked_add(extra)
        .ok_or(SnapshotError::VarIntOverflow)
}

fn check_limit(resource: &'static str, actual: u64, limit: u64) -> Result<(), SnapshotError> {
    if actual > limit {
        return Err(SnapshotError::LimitExceeded {
            resource,
            actual,
            limit,
        });
    }
    Ok(())
}

struct Decoder<'a, R> {
    reader: &'a mut R,
    consumed: u64,
    max_bytes: u64,
    script_bytes: u64,
}

impl<'a, R: Read> Decoder<'a, R> {
    const fn new(reader: &'a mut R, max_bytes: u64) -> Self {
        Self {
            reader,
            consumed: 0,
            max_bytes,
            script_bytes: 0,
        }
    }

    fn read_into(&mut self, mut bytes: &mut [u8]) -> Result<(), SnapshotError> {
        let wanted = self
            .consumed
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .ok_or(SnapshotError::LimitExceeded {
                resource: "encoded bytes",
                actual: u64::MAX,
                limit: self.max_bytes,
            })?;
        check_limit("encoded bytes", wanted, self.max_bytes)?;
        while !bytes.is_empty() {
            match self.reader.read(bytes) {
                Ok(0) => {
                    return Err(SnapshotError::Truncated {
                        offset: self.consumed,
                    });
                }
                Ok(n) => {
                    self.consumed += u64::try_from(n).unwrap_or(0);
                    bytes = &mut bytes[n..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(SnapshotError::Io(error)),
            }
        }
        Ok(())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SnapshotError> {
        let mut bytes = [0; N];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }

    fn metadata(&mut self) -> Result<SnapshotMetadata, SnapshotError> {
        if self.array::<5>()? != MAGIC {
            return Err(SnapshotError::InvalidMagic);
        }
        let version = u16::from_le_bytes(self.array()?);
        if version != VERSION {
            return Err(SnapshotError::UnsupportedVersion { version });
        }
        Ok(SnapshotMetadata {
            version,
            network_magic: self.array()?,
            base_block_hash: Hash256::from_le_bytes(&self.array()?),
            coins_count: u64::from_le_bytes(self.array()?),
        })
    }

    fn compact_size(&mut self) -> Result<u64, SnapshotError> {
        let first = self.array::<1>()?[0];
        let size = match first {
            0xfd => 3,
            0xfe => 5,
            0xff => 9,
            _ => 1,
        };
        let mut bytes = [0; 9];
        bytes[0] = first;
        self.read_into(&mut bytes[1..size])?;
        let (value, _) =
            varint::decode(&bytes[..size]).map_err(|_| SnapshotError::NonCanonicalCompactSize)?;
        if value > MAX_COMPACT_SIZE {
            return Err(SnapshotError::CompactSizeTooLarge { value });
        }
        Ok(value)
    }

    fn core_varint(&mut self, maximum: u64) -> Result<u64, SnapshotError> {
        let mut value = 0_u64;
        for _ in 0..10 {
            let byte = self.array::<1>()?[0];
            value = value
                .checked_mul(128)
                .and_then(|v| v.checked_add(u64::from(byte & 0x7f)))
                .ok_or(SnapshotError::VarIntOverflow)?;
            if byte & 0x80 == 0 {
                return (value <= maximum)
                    .then_some(value)
                    .ok_or(SnapshotError::VarIntOverflow);
            }
            value = value.checked_add(1).ok_or(SnapshotError::VarIntOverflow)?;
            if value > maximum {
                return Err(SnapshotError::VarIntOverflow);
            }
        }
        Err(SnapshotError::VarIntOverflow)
    }

    fn script(&mut self, max_script_bytes: u64) -> Result<Vec<u8>, SnapshotError> {
        let code = self.core_varint(u64::from(u32::MAX))?;
        let length = match code {
            0 => 25,
            1 => 23,
            2 | 3 => 35,
            4 | 5 => 67,
            _ => code - 6,
        };
        if length > MAX_SCRIPT_BYTES {
            return Err(SnapshotError::InvalidScriptLength { length });
        }
        let total = self
            .script_bytes
            .checked_add(length)
            .ok_or(SnapshotError::LimitExceeded {
                resource: "decoded script bytes",
                actual: u64::MAX,
                limit: max_script_bytes,
            })?;
        check_limit("decoded script bytes", total, max_script_bytes)?;
        self.script_bytes = total;
        let mut script = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
        match code {
            0 => {
                script.extend_from_slice(&[0x76, 0xa9, 0x14]);
                script.extend_from_slice(&self.array::<20>()?);
                script.extend_from_slice(&[0x88, 0xac]);
            }
            1 => {
                script.extend_from_slice(&[0xa9, 0x14]);
                script.extend_from_slice(&self.array::<20>()?);
                script.push(0x87);
            }
            2 | 3 => {
                script.extend_from_slice(&[0x21, u8::try_from(code).unwrap_or(0)]);
                script.extend_from_slice(&self.array::<32>()?);
                script.push(0xac);
            }
            4 | 5 => {
                let mut compressed = [0; 33];
                compressed[0] = u8::try_from(code - 2).unwrap_or(0);
                compressed[1..].copy_from_slice(&self.array::<32>()?);
                let pubkey = secp256k1::PublicKey::from_slice(&compressed)
                    .map_err(|_| SnapshotError::InvalidPublicKey)?;
                script.push(0x41);
                script.extend_from_slice(&pubkey.serialize_uncompressed());
                script.push(0xac);
            }
            _ => {
                script.resize(usize::try_from(length).unwrap_or(0), 0);
                self.read_into(&mut script)?;
            }
        }
        Ok(script)
    }

    #[cfg(test)]
    fn coins(
        &mut self,
        count: u64,
        base_height: u32,
        limits: SnapshotLimits,
    ) -> Result<(Vec<UtxoRecord>, Hash256), SnapshotError> {
        let mut records = Vec::new();
        let hash_serialized = self.coins_into(count, base_height, limits, |_, record| {
            records.push(record);
            Ok(())
        })?;
        Ok((records, hash_serialized))
    }

    fn coins_into(
        &mut self,
        count: u64,
        base_height: u32,
        limits: SnapshotLimits,
        mut sink: impl FnMut(Hash256, UtxoRecord) -> Result<(), SnapshotError>,
    ) -> Result<Hash256, SnapshotError> {
        check_limit("coins", count, limits.max_coins)?;
        check_limit(
            "addressable coins",
            count,
            u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        )?;
        let mut commitment = SerializedUtxoHasher::new();
        let mut remaining = count;
        let mut previous_txid: Option<[u8; 32]> = None;
        while remaining > 0 {
            let txid_bytes = self.array::<32>()?;
            if previous_txid.is_some_and(|previous| previous >= txid_bytes) {
                return Err(SnapshotError::TransactionOrder);
            }
            let txid = Hash256::from_le_bytes(&txid_bytes);
            previous_txid = Some(txid_bytes);
            let group = self.compact_size()?;
            if group == 0 {
                return Err(SnapshotError::EmptyGroup);
            }
            if group > remaining {
                return Err(SnapshotError::CoinCountMismatch { group, remaining });
            }
            check_limit(
                "coins per txid",
                group,
                u64::from(limits.max_coins_per_txid),
            )?;
            let mut outputs = Vec::new();
            for _ in 0..group {
                let raw_vout = self.compact_size()?;
                let vout = u32::try_from(raw_vout)
                    .ok()
                    .filter(|value| *value != u32::MAX)
                    .ok_or(SnapshotError::InvalidOutpoint { vout: raw_vout })?;
                let code = u32::try_from(self.core_varint(u64::from(u32::MAX))?)
                    .map_err(|_| SnapshotError::VarIntOverflow)?;
                let height = code >> 1;
                if height > base_height {
                    return Err(SnapshotError::InvalidHeight {
                        height,
                        base_height,
                    });
                }
                let compressed = self.core_varint(u64::MAX)?;
                let amount = crate::utxo::compress::decompress_amount(compressed)
                    .ok_or(SnapshotError::InvalidAmount { compressed })?;
                let script = self.script(limits.max_script_bytes)?;
                outputs.push(OwnedUtxoOut::new(
                    vout,
                    amount,
                    script,
                    code & 1 != 0,
                    height,
                ));
            }
            outputs.sort_unstable_by_key(|output| output.vout);
            for pair in outputs.windows(2) {
                if pair[0].vout == pair[1].vout {
                    return Err(SnapshotError::DuplicateOutpoint { vout: pair[0].vout });
                }
            }
            let record = UtxoRecord::from_owned_outputs(txid, &outputs)?;
            for output in record.outputs() {
                commitment.add(txid_bytes, output, Some(base_height))?;
            }
            sink(txid, record)?;
            remaining -= group;
        }
        Ok(commitment.finish())
    }

    fn end(&mut self) -> Result<(), SnapshotError> {
        let mut byte = [0];
        loop {
            match self.reader.read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err(SnapshotError::TrailingBytes),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(SnapshotError::Io(error)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::io::{self, Cursor, Read};

    use bitcoin_rs_consensus::primitives::{Hash256, Network, OutPoint, varint};

    use super::{
        CoreV2Base, Decoder, SnapshotError, SnapshotLimits, read_and_verify, read_metadata,
        write_core_v2,
    };
    use crate::utxo::record::{OwnedUtxoOut, UtxoRecord};

    const CORE: &[u8] = include_bytes!("../../../../testdata/storage/fixtures/core-v2/core200.dat");

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = core::str::from_utf8(pair).expect("hex text");
                u8::from_str_radix(text, 16).expect("hex byte")
            })
            .collect()
    }

    fn core_varint(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            bytes.push(
                u8::try_from(value & 0x7f).expect("seven bits")
                    | if bytes.is_empty() { 0 } else { 0x80 },
            );
            if value <= 0x7f {
                break;
            }
            value = (value >> 7) - 1;
        }
        bytes.reverse();
        bytes
    }

    fn script(bytes: &[u8]) -> Result<Vec<u8>, SnapshotError> {
        Decoder::new(&mut Cursor::new(bytes), 20_000).script(20_000)
    }

    fn body(bytes: &[u8], count: u64) -> Result<crate::utxo::UtxoSet, SnapshotError> {
        let (records, _) = Decoder::new(&mut Cursor::new(bytes), 1_000_000).coins(
            count,
            200,
            SnapshotLimits::default(),
        )?;
        let set = crate::utxo::UtxoSet::new();
        for record in records {
            set.insert_parsed_record(record);
        }
        Ok(set)
    }

    fn group(txid: u8, indices: &[u64]) -> Vec<u8> {
        let mut bytes = vec![txid; 32];
        bytes.extend_from_slice(
            varint::encode(u64::try_from(indices.len()).expect("test index count")).as_slice(),
        );
        for index in indices {
            bytes.extend_from_slice(varint::encode(*index).as_slice());
            bytes.extend_from_slice(&[3, 50, 7, 0x51]);
        }
        bytes
    }

    #[test]
    fn genuine_core_dump_matches_compiled_anchor_and_full_state() {
        let loaded = read_and_verify(
            &mut Cursor::new(CORE),
            Network::Regtest,
            SnapshotLimits::default(),
        )
        .expect("Core-produced fixture");
        assert_eq!(loaded.metadata.coins_count, 200);
        assert_eq!(loaded.set.len(), 200);
        assert_eq!(loaded.anchor.height, 200);
        assert_eq!(loaded.anchor.chain_tx_count, 201);
        assert_eq!(loaded.hash_serialized, loaded.anchor.hash_serialized);
        assert_eq!(
            loaded
                .set
                .lock_stable_view()
                .hash_serialized_3()
                .expect("materialized commitment"),
            loaded.hash_serialized,
            "staging and stable-view traversals share the Core commitment",
        );
        assert_eq!(loaded.bytes_read, 14_439);
        assert_eq!(
            loaded.metadata.base_block_hash.to_string(),
            "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"
        );
        assert_eq!(
            loaded.hash_serialized.to_string(),
            "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"
        );
        let total = loaded.set.with_stable_view(|view| {
            let mut total = 0_u64;
            view.for_each_all(|outpoint, _| {
                total += view
                    .get_entry(outpoint)
                    .expect("observed coin")
                    .txout
                    .value
                    .to_sat();
            });
            total
        });
        assert_eq!(total, 872_500_000_000);
    }

    #[test]
    fn inspection_reads_only_fixed_header_without_claiming_trust() {
        let mut input = Cursor::new(&CORE[..51]);
        let metadata = read_metadata(&mut input).expect("header without body");
        assert_eq!(input.position(), 51);
        assert_eq!(metadata.version, 2);
        assert_eq!(metadata.network_magic, Network::Regtest.magic());
        assert_eq!(metadata.coins_count, 200);
        let mut unpinned = CORE[..51].to_vec();
        unpinned[11..43].fill(0);
        assert_eq!(
            read_metadata(&mut Cursor::new(unpinned))
                .expect("untrusted header")
                .base_block_hash,
            Hash256::default()
        );
    }

    #[test]
    fn core_varint_reference_boundaries_are_not_record_leb128() {
        for (bytes, expected) in [
            (vec![0], 0),
            (vec![0x7f], 127),
            (vec![0x80, 0], 128),
            (vec![0xff, 0x7f], 16_511),
            (vec![0x80, 0x80, 0], 16_512),
        ] {
            let actual = Decoder::new(&mut Cursor::new(&bytes), 10)
                .core_varint(u64::MAX)
                .expect("Core VARINT");
            assert_eq!(actual, expected);
        }
        assert!(matches!(
            Decoder::new(&mut Cursor::new([0xff; 10]), 10).core_varint(u64::MAX),
            Err(SnapshotError::VarIntOverflow)
        ));
        assert!(matches!(
            Decoder::new(&mut Cursor::new(core_varint(u64::from(u32::MAX) + 1)), 10)
                .core_varint(u64::from(u32::MAX)),
            Err(SnapshotError::VarIntOverflow)
        ));
    }

    #[test]
    fn all_core_script_encodings_and_invalid_compressed_pubkeys_preserve_bytes() {
        let payload = vec![0x11; 20];
        for (code, prefix, suffix) in [
            (0, vec![0x76, 0xa9, 0x14], vec![0x88, 0xac]),
            (1, vec![0xa9, 0x14], vec![0x87]),
        ] {
            let mut encoded = vec![code];
            encoded.extend_from_slice(&payload);
            let mut expected = prefix;
            expected.extend_from_slice(&payload);
            expected.extend_from_slice(&suffix);
            assert_eq!(script(&encoded).expect("hash script"), expected);
        }
        for code in [2, 3] {
            let mut encoded = vec![code];
            encoded.extend_from_slice(&[0xff; 32]);
            let mut expected = vec![0x21, code];
            expected.extend_from_slice(&[0xff; 32]);
            expected.push(0xac);
            assert_eq!(
                script(&encoded).expect("opaque compressed pubkey"),
                expected
            );
        }
        let x = hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        for (code, y) in [
            (
                4,
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            ),
            (
                5,
                "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777",
            ),
        ] {
            let mut encoded = vec![code];
            encoded.extend_from_slice(&x);
            let mut expected = vec![0x41, 4];
            expected.extend_from_slice(&x);
            expected.extend_from_slice(&hex(y));
            expected.push(0xac);
            assert_eq!(
                script(&encoded).expect("uncompressed curve point"),
                expected
            );
            encoded[1..].fill(0xff);
            assert!(matches!(
                script(&encoded),
                Err(SnapshotError::InvalidPublicKey)
            ));
        }
        assert_eq!(script(&[6]).expect("empty script"), Vec::<u8>::new());
        assert_eq!(script(&[7, 0x51]).expect("raw script"), vec![0x51]);
        let mut maximum = core_varint(10_006);
        maximum.extend_from_slice(&vec![0x51; 10_000]);
        assert_eq!(script(&maximum).expect("maximum script").len(), 10_000);
        assert!(matches!(
            script(&core_varint(10_007)),
            Err(SnapshotError::InvalidScriptLength { length: 10_001 })
        ));
        for code in 0..=5 {
            assert!(matches!(
                script(&[code]),
                Err(SnapshotError::Truncated { .. })
            ));
        }
    }

    #[test]
    fn coin_count_is_outputs_not_transaction_records() {
        let set = body(&group(1, &[0, 2]), 2).expect("two coins in one txid");
        assert_eq!(set.record_count(), 1);
        assert_eq!(set.len(), 2);
        let txid = Hash256::from_le_bytes(&[1; 32]);
        let coin = set
            .lock_stable_view()
            .get_entry(&OutPoint::new(txid.into(), 2))
            .expect("second output");
        assert_eq!(coin.txout.value.to_sat(), 5_000_000_000);
        assert_eq!(coin.height, 1);
        assert!(coin.coinbase);
    }

    #[test]
    fn structure_and_record_semantics_fail_closed() {
        assert!(matches!(
            body(&group(1, &[]), 1),
            Err(SnapshotError::EmptyGroup)
        ));
        assert!(matches!(
            body(&group(1, &[0, 1]), 1),
            Err(SnapshotError::CoinCountMismatch { .. })
        ));
        assert!(matches!(
            body(&group(1, &[0, 0]), 2),
            Err(SnapshotError::DuplicateOutpoint { vout: 0 })
        ));
        for next in [0, 1] {
            let mut bytes = group(1, &[0]);
            bytes.extend(group(next, &[1]));
            assert!(matches!(
                body(&bytes, 2),
                Err(SnapshotError::TransactionOrder)
            ));
        }
        let mut too_high = group(1, &[0]);
        too_high.splice(34..35, core_varint(402));
        assert!(matches!(
            body(&too_high, 1),
            Err(SnapshotError::InvalidHeight { height: 201, .. })
        ));
        let mut bad_amount = group(1, &[0]);
        bad_amount.splice(35..36, core_varint(u64::MAX));
        assert!(matches!(
            body(&bad_amount, 1),
            Err(SnapshotError::InvalidAmount { .. })
        ));
        let mut noncanonical = vec![1; 32];
        noncanonical.extend_from_slice(&[0xfd, 1, 0]);
        assert!(matches!(
            body(&noncanonical, 1),
            Err(SnapshotError::NonCanonicalCompactSize)
        ));
        assert!(matches!(
            body(&group(1, &[u64::from(u32::MAX)]), 1),
            Err(SnapshotError::CompactSizeTooLarge { .. })
        ));
    }

    #[test]
    fn all_limits_are_enforced_including_aggregate_scripts_and_header_bytes() {
        let defaults = SnapshotLimits::default();
        for (limits, resource) in [
            (
                SnapshotLimits {
                    max_file_bytes: 50,
                    ..defaults
                },
                "encoded bytes",
            ),
            (
                SnapshotLimits {
                    max_file_bytes: 14_438,
                    ..defaults
                },
                "encoded bytes",
            ),
            (
                SnapshotLimits {
                    max_coins: 199,
                    ..defaults
                },
                "coins",
            ),
            (
                SnapshotLimits {
                    max_script_bytes: 6_799,
                    ..defaults
                },
                "decoded script bytes",
            ),
            (
                SnapshotLimits {
                    max_coins_per_txid: 0,
                    ..defaults
                },
                "coins per txid",
            ),
        ] {
            assert!(
                matches!(read_and_verify(&mut Cursor::new(CORE), Network::Regtest, limits), Err(SnapshotError::LimitExceeded { resource: actual, .. }) if actual == resource)
            );
        }
        let exact = SnapshotLimits {
            max_file_bytes: 14_439,
            max_coins: 200,
            max_script_bytes: 6_800,
            max_coins_per_txid: 1,
        };
        assert!(read_and_verify(&mut Cursor::new(CORE), Network::Regtest, exact).is_ok());
        let mut reader = Cursor::new(group(1, &[0, 1]));
        let error = Decoder::new(&mut reader, 1000).coins(
            2,
            200,
            SnapshotLimits {
                max_coins_per_txid: 1,
                ..defaults
            },
        );
        assert!(matches!(
            error,
            Err(SnapshotError::LimitExceeded {
                resource: "coins per txid",
                ..
            })
        ));
        assert_eq!(
            reader.position(),
            33,
            "reject a group before allocating outputs"
        );
    }

    #[test]
    fn corrupted_core_artifacts_and_untrusted_headers_are_rejected() {
        for offset in [0, 4, 5, 6, 10, 42, 50, 51, CORE.len() - 1] {
            assert!(matches!(
                read_and_verify(
                    &mut Cursor::new(&CORE[..offset]),
                    Network::Regtest,
                    SnapshotLimits::default()
                ),
                Err(SnapshotError::Truncated { .. })
            ));
        }
        let mut bytes = CORE.to_vec();
        bytes[0] ^= 1;
        assert!(matches!(
            read_metadata(&mut Cursor::new(&bytes)),
            Err(SnapshotError::InvalidMagic)
        ));
        bytes = CORE.to_vec();
        bytes[5] = 3;
        assert!(matches!(
            read_metadata(&mut Cursor::new(&bytes)),
            Err(SnapshotError::UnsupportedVersion { version: 3 })
        ));
        assert!(matches!(
            read_and_verify(
                &mut Cursor::new(CORE),
                Network::Mainnet,
                SnapshotLimits::default()
            ),
            Err(SnapshotError::WrongNetwork { .. })
        ));
        bytes = CORE.to_vec();
        bytes[11..43].fill(0);
        assert!(matches!(
            read_and_verify(
                &mut Cursor::new(&bytes),
                Network::Regtest,
                SnapshotLimits::default()
            ),
            Err(SnapshotError::UnsupportedAnchor { .. })
        ));
        bytes = CORE.to_vec();
        bytes.push(0);
        assert!(matches!(
            read_and_verify(
                &mut Cursor::new(&bytes),
                Network::Regtest,
                SnapshotLimits::default()
            ),
            Err(SnapshotError::TrailingBytes)
        ));
        bytes = CORE.to_vec();
        bytes[43..51].copy_from_slice(&199_u64.to_le_bytes());
        assert!(matches!(
            read_and_verify(
                &mut Cursor::new(&bytes),
                Network::Regtest,
                SnapshotLimits::default()
            ),
            Err(SnapshotError::TrailingBytes)
        ));
        bytes[43..51].copy_from_slice(&201_u64.to_le_bytes());
        assert!(matches!(
            read_and_verify(
                &mut Cursor::new(&bytes),
                Network::Regtest,
                SnapshotLimits::default()
            ),
            Err(SnapshotError::Truncated { .. })
        ));
        bytes = CORE.to_vec();
        *bytes.last_mut().expect("fixture byte") ^= 1;
        assert!(matches!(
            read_and_verify(
                &mut Cursor::new(&bytes),
                Network::Regtest,
                SnapshotLimits::default()
            ),
            Err(SnapshotError::CommitmentMismatch { .. })
        ));
    }

    #[test]
    fn short_reads_interrupts_and_io_failures_keep_their_meaning() {
        struct Short<'a> {
            input: &'a [u8],
            interrupted: bool,
        }
        impl Read for Short<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let n = buf.len().min(1);
                self.input.read(&mut buf[..n])
            }
        }
        struct Failed;
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        let mut short = Short {
            input: CORE,
            interrupted: false,
        };
        assert!(read_and_verify(&mut short, Network::Regtest, SnapshotLimits::default()).is_ok());
        assert!(
            matches!(read_metadata(&mut Failed), Err(SnapshotError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
    }

    #[test]
    fn forged_collision_families_never_enter_the_utxo_hash_table() {
        const RECORDS: u32 = 4096;
        for same_full_hash in [true, false] {
            let mut bytes = CORE[..51].to_vec();
            bytes[43..51].copy_from_slice(&u64::from(RECORDS).to_le_bytes());
            for index in 0..RECORDS {
                let mut record = group(0, &[0]);
                if same_full_hash {
                    record[8..12].copy_from_slice(&index.to_be_bytes());
                } else {
                    record[4..7].copy_from_slice(&index.to_be_bytes()[1..]);
                }
                bytes.extend(record);
            }
            let before = crate::utxo::set::PARSED_RECORD_INSERTIONS.with(std::cell::Cell::get);
            assert!(matches!(
                read_and_verify(
                    &mut Cursor::new(&bytes),
                    Network::Regtest,
                    SnapshotLimits::default()
                ),
                Err(SnapshotError::CommitmentMismatch { .. })
            ));
            assert_eq!(
                crate::utxo::set::PARSED_RECORD_INSERTIONS.with(std::cell::Cell::get),
                before
            );
        }
        let before = crate::utxo::set::PARSED_RECORD_INSERTIONS.with(std::cell::Cell::get);
        assert!(
            read_and_verify(
                &mut Cursor::new(CORE),
                Network::Regtest,
                SnapshotLimits::default()
            )
            .is_ok()
        );
        assert_eq!(
            crate::utxo::set::PARSED_RECORD_INSERTIONS.with(std::cell::Cell::get),
            before + 200
        );
    }

    #[test]
    fn staged_records_sort_vouts_and_move_their_payloads_without_copying() {
        let bytes = group(1, &[9, 1, 3]);
        let (records, hash) = Decoder::new(&mut Cursor::new(bytes), 1000)
            .coins(3, 200, SnapshotLimits::default())
            .expect("bounded staged records");
        assert_eq!(
            records[0]
                .outputs()
                .map(|output| output.vout)
                .collect::<Vec<_>>(),
            vec![1, 3, 9]
        );
        let first_script = records[0]
            .outputs()
            .next()
            .expect("first coin")
            .script_pubkey
            .as_ptr();
        let set = crate::utxo::UtxoSet::new();
        for record in records {
            set.insert_parsed_record(record);
        }
        set.with_stable_view(|view| {
            assert_eq!(view.hash_serialized_3().expect("stable-view hash"), hash);
            view.for_each_all(|outpoint, script| {
                if outpoint.vout == 1 {
                    assert_eq!(script.as_ptr(), first_script, "record payload was moved");
                }
            });
        });
        assert!(matches!(
            body(&group(1, &[1, 9, 1]), 3),
            Err(SnapshotError::DuplicateOutpoint { vout: 1 })
        ));
    }

    #[test]
    fn writer_emits_byte_identical_core200_snapshot_and_roundtrips_read_and_verify() {
        let loaded = read_and_verify(
            &mut Cursor::new(CORE),
            Network::Regtest,
            SnapshotLimits::default(),
        )
        .expect("load fixture snapshot");

        let mut written = Vec::new();
        let report = loaded
            .set
            .with_stable_view(|view| {
                write_core_v2(
                    view,
                    &CoreV2Base {
                        network: Network::Regtest,
                        base_hash: loaded.metadata.base_block_hash,
                        base_height: loaded.anchor.height,
                        coins_count: loaded.metadata.coins_count,
                    },
                    &mut written,
                    &|| false,
                )
            })
            .expect("write_core_v2 succeeds");

        assert_eq!(report.bytes, u64::try_from(CORE.len()).expect("fit"));
        assert_eq!(report.coins, 200);
        assert_eq!(report.txoutset_hash, loaded.hash_serialized);
        assert_eq!(written.len(), CORE.len());
        assert_eq!(written, CORE);

        let reloaded = read_and_verify(
            &mut Cursor::new(&written),
            Network::Regtest,
            SnapshotLimits::default(),
        )
        .expect("round-trip read_and_verify");
        assert_eq!(reloaded.hash_serialized, loaded.hash_serialized);
        assert_eq!(reloaded.metadata, loaded.metadata);
        assert_eq!(reloaded.bytes_read, report.bytes);
    }

    #[test]
    fn writer_script_compression_encodes_odd_even_y_and_offcurve_fallback() {
        let set = crate::utxo::UtxoSet::new();

        let gx = hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let even_y = hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
        let odd_y = hex("b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777");

        let mut p2pk_even = vec![0x41, 0x04];
        p2pk_even.extend_from_slice(&gx);
        p2pk_even.extend_from_slice(&even_y);
        p2pk_even.push(0xac);

        let mut p2pk_odd = vec![0x41, 0x04];
        p2pk_odd.extend_from_slice(&gx);
        p2pk_odd.extend_from_slice(&odd_y);
        p2pk_odd.push(0xac);

        let mut p2pk_offcurve = p2pk_even.clone();
        p2pk_offcurve[2..34].fill(0xff);

        let mut p2pk_comp = vec![0x21, 0x02];
        p2pk_comp.extend_from_slice(&gx);
        p2pk_comp.push(0xac);

        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[0x22; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);

        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&[0x33; 20]);
        p2sh.push(0x87);

        let scripts = [p2pk_even, p2pk_odd, p2pk_offcurve, p2pk_comp, p2pkh, p2sh];
        for (i, script) in scripts.iter().enumerate() {
            let mut txid_bytes = [0_u8; 32];
            txid_bytes[0] = u8::try_from(i).expect("fit");
            txid_bytes[1] = 0xaa;
            let txid = Hash256::from_le_bytes(&txid_bytes);
            let out = OwnedUtxoOut::new(0, 50_000_000, script.clone(), false, 1);
            let record = UtxoRecord::from_owned_outputs(txid, &[out]).expect("record");
            set.insert_parsed_record(record);
        }

        let mut written = Vec::new();
        let base_hash = Hash256::from_le_bytes(&[0x42; 32]);
        let report = set
            .with_stable_view(|view| {
                write_core_v2(
                    view,
                    &CoreV2Base {
                        network: Network::Regtest,
                        base_hash,
                        base_height: 100,
                        coins_count: 6,
                    },
                    &mut written,
                    &|| false,
                )
            })
            .expect("write succeeds");
        assert_eq!(report.coins, 6);

        let mut cursor = Cursor::new(&written);
        let mut decoder = Decoder::new(&mut cursor, u64::try_from(written.len()).expect("fit"));
        let meta = decoder.metadata().expect("meta");
        assert_eq!(meta.coins_count, 6);
        let (records, hash) = decoder
            .coins(6, 100, SnapshotLimits::default())
            .expect("coins");
        assert_eq!(hash, report.txoutset_hash);
        assert_eq!(records.len(), 6);
        for (i, record) in records.iter().enumerate() {
            let out = record.outputs().next().expect("out");
            assert_eq!(out.script_pubkey, scripts[i].as_slice());
        }
    }

    #[test]
    fn writer_cancellation_polls_a_large_set() {
        let loaded = read_and_verify(
            &mut Cursor::new(CORE),
            Network::Regtest,
            SnapshotLimits::default(),
        )
        .expect("fixture");

        let mut written = Vec::new();
        let res = loaded.set.with_stable_view(|view| {
            write_core_v2(
                view,
                &CoreV2Base {
                    network: Network::Regtest,
                    base_hash: loaded.metadata.base_block_hash,
                    base_height: loaded.anchor.height,
                    coins_count: loaded.metadata.coins_count,
                },
                &mut written,
                &|| true,
            )
        });
        assert!(matches!(res, Err(SnapshotError::Interrupted)));

        let large_set = crate::utxo::UtxoSet::new();
        for i in 0..5_005_u32 {
            let mut txid_bytes = [0_u8; 32];
            txid_bytes[0] = u8::try_from(i & 0xff).expect("fit");
            txid_bytes[1..5].copy_from_slice(&i.to_le_bytes());
            let txid = Hash256::from_le_bytes(&txid_bytes);
            let out = OwnedUtxoOut::new(0, 1000, vec![0x51], false, 1);
            let record = UtxoRecord::from_owned_outputs(txid, &[out]).expect("record");
            large_set.insert_parsed_record(record);
        }

        let poll_called = std::cell::Cell::new(false);
        let mut written_large = Vec::new();
        let res_large = large_set.with_stable_view(|view| {
            write_core_v2(
                view,
                &CoreV2Base {
                    network: Network::Regtest,
                    base_hash: loaded.metadata.base_block_hash,
                    base_height: 100,
                    coins_count: 5005,
                },
                &mut written_large,
                &|| {
                    if poll_called.get() {
                        true
                    } else {
                        poll_called.set(true);
                        false
                    }
                },
            )
        });
        assert!(matches!(res_large, Err(SnapshotError::Interrupted)));
        assert!(poll_called.get());
    }

    #[test]
    fn writer_declared_coin_count_mismatch_fails_closed() {
        let loaded = read_and_verify(
            &mut Cursor::new(CORE),
            Network::Regtest,
            SnapshotLimits::default(),
        )
        .expect("fixture");

        let mut written = Vec::new();
        let res_low = loaded.set.with_stable_view(|view| {
            write_core_v2(
                view,
                &CoreV2Base {
                    network: Network::Regtest,
                    base_hash: loaded.metadata.base_block_hash,
                    base_height: loaded.anchor.height,
                    coins_count: 100,
                },
                &mut written,
                &|| false,
            )
        });
        assert!(matches!(
            res_low,
            Err(SnapshotError::DeclaredCoinCountMismatch {
                declared: 100,
                actual: 101
            })
        ));

        written.clear();
        let res_high = loaded.set.with_stable_view(|view| {
            write_core_v2(
                view,
                &CoreV2Base {
                    network: Network::Regtest,
                    base_hash: loaded.metadata.base_block_hash,
                    base_height: loaded.anchor.height,
                    coins_count: 300,
                },
                &mut written,
                &|| false,
            )
        });
        assert!(matches!(
            res_high,
            Err(SnapshotError::DeclaredCoinCountMismatch {
                declared: 300,
                actual: 200
            })
        ));
    }

    #[test]
    fn writer_io_failure_propagates_as_snapshot_error() {
        struct FailingWriter {
            fail_after: usize,
            written: usize,
        }
        impl std::io::Write for FailingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.written + buf.len() > self.fail_after {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "simulated write failure",
                    ))
                } else {
                    self.written += buf.len();
                    Ok(buf.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let loaded = read_and_verify(
            &mut Cursor::new(CORE),
            Network::Regtest,
            SnapshotLimits::default(),
        )
        .expect("fixture");

        let mut failing = FailingWriter {
            fail_after: 20,
            written: 0,
        };
        let res = loaded.set.with_stable_view(|view| {
            write_core_v2(
                view,
                &CoreV2Base {
                    network: Network::Regtest,
                    base_hash: loaded.metadata.base_block_hash,
                    base_height: loaded.anchor.height,
                    coins_count: loaded.metadata.coins_count,
                },
                &mut failing,
                &|| false,
            )
        });
        assert!(matches!(res, Err(SnapshotError::Io(_))));

        let mut failing_coins = FailingWriter {
            fail_after: 100,
            written: 0,
        };
        let res_coins = loaded.set.with_stable_view(|view| {
            write_core_v2(
                view,
                &CoreV2Base {
                    network: Network::Regtest,
                    base_hash: loaded.metadata.base_block_hash,
                    base_height: loaded.anchor.height,
                    coins_count: loaded.metadata.coins_count,
                },
                &mut failing_coins,
                &|| false,
            )
        });
        assert!(matches!(res_coins, Err(SnapshotError::Io(_))));
    }

    #[test]
    fn writer_rejects_output_with_max_vout_as_invalid_outpoint() {
        let set = crate::utxo::UtxoSet::new();
        let txid = Hash256::from_le_bytes(&[0x5a; 32]);
        let out = OwnedUtxoOut::new(u32::MAX, 50_000_000, vec![0x51], false, 1);
        let record =
            UtxoRecord::from_owned_outputs(txid, &[out]).expect("UtxoRecord admits u32::MAX vout");
        set.insert_parsed_record(record);

        let mut written = Vec::new();
        let base_hash = Hash256::from_le_bytes(&[0x42; 32]);
        let res = set.with_stable_view(|view| {
            write_core_v2(
                view,
                &CoreV2Base {
                    network: Network::Regtest,
                    base_hash,
                    base_height: 100,
                    coins_count: 1,
                },
                &mut written,
                &|| false,
            )
        });

        let error = res.expect_err("write_core_v2 must reject output with vout u32::MAX");
        match error {
            SnapshotError::InvalidOutpoint { vout } => {
                assert_eq!(vout, u64::from(u32::MAX));
            }
            other => panic!("expected InvalidOutpoint error, got {other:?}"),
        }
    }

    #[test]
    fn writer_encodes_highest_encodable_height_for_both_coinbase_variants() {
        let max_height: u32 = 0x7fff_ffff;
        let base_hash = Hash256::from_le_bytes(&[0x33; 32]);

        for coinbase in [false, true] {
            let set = crate::utxo::UtxoSet::new();
            let txid = Hash256::from_le_bytes(&[if coinbase { 0x11 } else { 0x22 }; 32]);
            let out = OwnedUtxoOut::new(0, 50_000_000, vec![0x51], coinbase, max_height);
            let record = UtxoRecord::from_owned_outputs(txid, &[out])
                .expect("UtxoRecord admits valid max height");
            set.insert_parsed_record(record);

            let mut written = Vec::new();
            let report = set
                .with_stable_view(|view| {
                    write_core_v2(
                        view,
                        &CoreV2Base {
                            network: Network::Regtest,
                            base_hash,
                            base_height: max_height,
                            coins_count: 1,
                        },
                        &mut written,
                        &|| false,
                    )
                })
                .expect("write_core_v2 must accept max encodable height");

            assert_eq!(report.coins, 1);
            assert!(report.bytes > 51);

            let (records, hash_serialized) =
                Decoder::new(&mut Cursor::new(&written[51..]), 1_000_000)
                    .coins(1, max_height, SnapshotLimits::default())
                    .expect("Decoder must accept snapshot written with max encodable height");

            assert_eq!(records.len(), 1);
            let outputs: Vec<_> = records[0].outputs().collect();
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].height, max_height);
            assert_eq!(outputs[0].coinbase, coinbase);
            assert_eq!(report.txoutset_hash, hash_serialized);
        }
    }

    #[test]
    fn writer_rejects_next_height_as_varint_overflow_for_both_coinbase_variants() {
        let overflow_height: u32 = 0x8000_0000;
        let base_hash = Hash256::from_le_bytes(&[0x44; 32]);

        for coinbase in [false, true] {
            let set = crate::utxo::UtxoSet::new();
            let txid = Hash256::from_le_bytes(&[if coinbase { 0xaa } else { 0xbb }; 32]);
            let out = OwnedUtxoOut::new(0, 50_000_000, vec![0x51], coinbase, overflow_height);
            let record = UtxoRecord::from_owned_outputs(txid, &[out])
                .expect("UtxoRecord admits height with bit 31 set");
            set.insert_parsed_record(record);

            let mut written = Vec::new();
            let res = set.with_stable_view(|view| {
                write_core_v2(
                    view,
                    &CoreV2Base {
                        network: Network::Regtest,
                        base_hash,
                        base_height: overflow_height,
                        coins_count: 1,
                    },
                    &mut written,
                    &|| false,
                )
            });

            match res {
                Err(SnapshotError::VarIntOverflow) => {}
                other => panic!(
                    "expected VarIntOverflow for height 0x8000_0000 (coinbase={coinbase}), got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn writer_preserves_invalid_height_precedence_over_varint_overflow() {
        let overflow_height: u32 = 0x8000_0000;
        let base_height: u32 = 100;
        let base_hash = Hash256::from_le_bytes(&[0x55; 32]);

        let set = crate::utxo::UtxoSet::new();
        let txid = Hash256::from_le_bytes(&[0xcc; 32]);
        let out = OwnedUtxoOut::new(0, 50_000_000, vec![0x51], false, overflow_height);
        let record = UtxoRecord::from_owned_outputs(txid, &[out])
            .expect("UtxoRecord admits height with bit 31 set");
        set.insert_parsed_record(record);

        let mut written = Vec::new();
        let res = set.with_stable_view(|view| {
            write_core_v2(
                view,
                &CoreV2Base {
                    network: Network::Regtest,
                    base_hash,
                    base_height,
                    coins_count: 1,
                },
                &mut written,
                &|| false,
            )
        });

        match res {
            Err(SnapshotError::InvalidHeight {
                height,
                base_height: base,
            }) => {
                assert_eq!(height, overflow_height);
                assert_eq!(base, base_height);
            }
            other => panic!("expected InvalidHeight error, got {other:?}"),
        }
    }

    #[test]
    fn core_file_cursor_order_and_hash_numeric_order_diverge_at_16512() {
        use core::cmp::Ordering;

        use crate::utxo::compress::cmp_core_varint_key;
        use crate::utxo::snapshot::SerializedUtxoHasher;

        assert_eq!(core_varint(16_511), vec![0xFF, 0x7F]);
        assert_eq!(core_varint(16_512), vec![0x80, 0x80, 0x00]);
        assert_eq!(cmp_core_varint_key(16_512, 16_511), Ordering::Less);
        assert_eq!(cmp_core_varint_key(16_511, 16_512), Ordering::Greater);
        assert_eq!(cmp_core_varint_key(0, 127), Ordering::Less);
        assert_eq!(cmp_core_varint_key(128, 16_511), Ordering::Less);
        assert_eq!(cmp_core_varint_key(16_512, 16_513), Ordering::Less);
        assert_eq!(cmp_core_varint_key(5, 5), Ordering::Equal);

        let bytes = group(7, &[16_511, 16_512]);
        let (records, hash) = Decoder::new(&mut Cursor::new(bytes), 100_000)
            .coins(2, 200, SnapshotLimits::default())
            .expect("staged records");
        assert_eq!(
            records[0]
                .outputs()
                .map(|output| output.vout)
                .collect::<Vec<_>>(),
            vec![16_511, 16_512]
        );
        let txid_bytes = Hash256::from_le_bytes(&[7; 32]).to_le_bytes();
        let staged: Vec<_> = records[0].outputs().collect();
        let mut numeric_feed = SerializedUtxoHasher::new();
        for output in &staged {
            numeric_feed
                .add(txid_bytes, *output, Some(200))
                .expect("numeric feed");
        }
        assert_eq!(numeric_feed.finish(), hash);
        let mut cursor_feed = SerializedUtxoHasher::new();
        for output in staged.iter().rev() {
            cursor_feed
                .add(txid_bytes, *output, Some(200))
                .expect("cursor feed");
        }
        assert_ne!(
            cursor_feed.finish(),
            hash,
            "the transition must distinguish cursor order from numeric order"
        );

        let set = crate::utxo::UtxoSet::new();
        let txid = Hash256::from_le_bytes(&[7; 32]);
        let low = OwnedUtxoOut::new(16_511, 5_000_000_000, vec![0x51], true, 1);
        let high = OwnedUtxoOut::new(16_512, 5_000_000_000, vec![0x51], true, 1);
        let record = UtxoRecord::from_owned_outputs(txid, &[low, high]).expect("record");
        set.insert_parsed_record(record);
        let base_hash = Hash256::from_le_bytes(&[0x77; 32]);
        let mut written = Vec::new();
        let report = set
            .with_stable_view(|view| {
                write_core_v2(
                    view,
                    &CoreV2Base {
                        network: Network::Regtest,
                        base_hash,
                        base_height: 200,
                        coins_count: 2,
                    },
                    &mut written,
                    &|| false,
                )
            })
            .expect("write succeeds");
        assert_eq!(written[84..87], [0xFD, 0x80, 0x40]);
        let mut cursor = Cursor::new(&written);
        let mut decoder = Decoder::new(&mut cursor, u64::try_from(written.len()).expect("fit"));
        decoder.metadata().expect("header");
        let (emitted, emitted_hash) = decoder
            .coins(2, 200, SnapshotLimits::default())
            .expect("re-decode");
        assert_eq!(
            emitted[0]
                .outputs()
                .map(|output| output.vout)
                .collect::<Vec<_>>(),
            vec![16_511, 16_512],
            "the decoder normalizes file cursor order to numeric order"
        );
        assert_eq!(emitted_hash, report.txoutset_hash);
        assert_eq!(emitted_hash, hash);
        set.with_stable_view(|view| {
            assert_eq!(view.hash_serialized_3().expect("stable-view hash"), hash);
        });

        assert!(matches!(
            body(&group(7, &[16_511, 16_511]), 2),
            Err(SnapshotError::DuplicateOutpoint { vout: 16_511 })
        ));
        assert!(matches!(
            body(&group(7, &[16_512, 16_511, 16_512]), 3),
            Err(SnapshotError::DuplicateOutpoint { vout: 16_512 })
        ));
    }
}

#[cfg(test)]
mod sealed_state_tests {
    use std::io::Cursor;

    use super::*;

    use crate::utxo::test_support::{TestError, TestResult};

    const CORE: &[u8] = include_bytes!("../../../../testdata/storage/fixtures/core-v2/core200.dat");

    fn sealed() -> Result<VerifiedCoreSnapshot, SnapshotError> {
        read_verified(
            &mut Cursor::new(CORE),
            Network::Regtest,
            SnapshotLimits::default(),
        )
    }

    fn bare() -> Result<CoreSnapshot, SnapshotError> {
        read_and_verify(
            &mut Cursor::new(CORE),
            Network::Regtest,
            SnapshotLimits::default(),
        )
    }

    #[test]
    fn folded_statistics_equal_an_independent_scan_of_the_sealed_set() -> TestResult {
        let snapshot = sealed()?;
        let anchor = snapshot.anchor;
        assert_eq!(snapshot.bytes_read, 14_439);
        let state = snapshot.into_state();
        assert_eq!(state.height(), anchor.height);
        assert_eq!(state.base_hash(), anchor.block_hash);
        assert_eq!(state.hash_serialized(), anchor.hash_serialized);
        let folded = state.stats().clone();
        let (set, _) = state.into_parts();
        let (commitment, scanned) = set.with_stable_view(|view| {
            Ok::<_, UtxoError>((
                view.hash_serialized_3_at_height(anchor.height)?,
                scan_coin_stats(view, anchor.height, true)?,
            ))
        })?;
        assert_eq!(commitment, anchor.hash_serialized);
        assert_eq!(folded.to_bytes(), scanned.to_bytes());
        assert_eq!(folded.utxo_count, 200);
        assert_eq!(folded.total_amount, 872_500_000_000);
        assert_eq!(folded.height, anchor.height);
        assert_eq!(folded.bogo_size, scanned.bogo_size);
        Ok(())
    }

    #[test]
    fn proofless_verification_seals_the_same_state_as_the_reader() -> TestResult {
        let loaded = bare()?;
        let anchor = loaded.anchor;
        let again = VerifiedSnapshotState::verify(loaded.set, anchor)?;
        let reader = sealed()?.into_state();
        assert_eq!(again.base_hash(), reader.base_hash());
        assert_eq!(again.height(), reader.height());
        assert_eq!(again.hash_serialized(), reader.hash_serialized());
        assert_eq!(again.stats().to_bytes(), reader.stats().to_bytes());
        Ok(())
    }

    #[test]
    fn proofless_verification_refuses_a_mutated_set_or_a_foreign_anchor() -> TestResult {
        let anchor = bare()?.anchor;
        let mutated_set = UtxoSet::new();
        assert!(matches!(
            VerifiedSnapshotState::verify(mutated_set, anchor),
            Err(StateVerifyError::CommitmentMismatch { expected, .. })
                if expected == anchor.hash_serialized
        ));
        let foreign = AssumeUtxoData {
            hash_serialized: Hash256::default(),
            ..*anchor
        };
        assert!(matches!(
            VerifiedSnapshotState::verify(bare()?.set, &foreign),
            Err(StateVerifyError::CommitmentMismatch { actual, .. })
                if actual == anchor.hash_serialized
        ));
        Ok(())
    }

    #[test]
    fn wrong_commitment_never_reaches_the_table_or_the_statistics() -> TestResult {
        let mut forged = CORE.to_vec();
        let last = forged
            .last_mut()
            .ok_or(TestError::Missing("empty fixture"))?;
        *last ^= 1;
        let before = crate::utxo::set::PARSED_RECORD_INSERTIONS.with(std::cell::Cell::get);
        assert!(matches!(
            read_verified(
                &mut Cursor::new(&forged),
                Network::Regtest,
                SnapshotLimits::default()
            ),
            Err(SnapshotError::CommitmentMismatch { .. })
        ));
        assert_eq!(
            crate::utxo::set::PARSED_RECORD_INSERTIONS.with(std::cell::Cell::get),
            before
        );
        drop(sealed()?);
        assert_eq!(
            crate::utxo::set::PARSED_RECORD_INSERTIONS.with(std::cell::Cell::get),
            before + 200
        );
        Ok(())
    }
}
