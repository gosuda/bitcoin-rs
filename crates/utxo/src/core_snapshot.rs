//! Bitcoin Core portable snapshot v2 input.
//!
//! The header is untrusted metadata. Full loading resolves a compiled network
//! anchor, checks the commitment of staged existing records, and only then
//! installs them into the existing UTXO set.
//!
//! [`read_verified`] is the activation reader. It returns a
//! [`VerifiedSnapshotState`]: one owned [`UtxoSet`] sealed together with the
//! commitment and [`CoinStats`] derived from exactly the authenticated records
//! that populated it. [`read_and_verify`] is the inspection reader that returns
//! the bare set for offline tools; its result carries no proof.
//! Native bitcoin-rs v4 checkpoint serialization is a separate format.

use std::io::{self, Read, Write};

use bitcoin_rs_primitives::{AssumeUtxoData, Hash256, Network, varint};
use thiserror::Error;

use crate::{
    UtxoError, UtxoSet, UtxoSetView,
    record::{OneUtxoOut, OwnedUtxoOut, UtxoRecord},
    snapshot::{SerializedUtxoHasher, SnapshotCoin, SnapshotCoinObserver},
    stats::{CoinStats, CoinStatsAccumulator, scan_coin_stats},
};

const MAGIC: [u8; 5] = *b"utxo\xff";
const VERSION: u16 = 2;
const HEADER_BYTES: u64 = 51;
const MAX_SCRIPT_BYTES: u64 = 10_000;
// Core ReadCompactSize's default range check.
const MAX_COMPACT_SIZE: u64 = 0x0200_0000;

/// Parsed header fields; parsing these fields does not authenticate the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// Supported portable format version (2).
    pub version: u16,
    /// Network message-start bytes as carried by the file.
    pub network_magic: [u8; 4],
    /// Untrusted base block identity, resolved against a compiled anchor on load.
    pub base_block_hash: Hash256,
    /// Declared number of live outputs, not transaction-level records.
    pub coins_count: u64,
}

/// Resource budgets enforced before growing decoded state.
///
/// Coin and aggregate script bounds constrain retained record payloads; the
/// per-txid bound also constrains temporary output sorting. Before authentication,
/// records live in a vector without a hash table. After authentication, payloads
/// move into the UTXO set while the vector's allocation is still retained.
/// These bounds are not an allocator/RSS quota: staging, hash tables and other
/// allocation overhead remain additional. Verification materializes state in RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotLimits {
    /// Maximum encoded bytes, including the header; at most one extra byte is
    /// read to distinguish exact EOF from forbidden trailing data.
    pub max_file_bytes: u64,
    /// Maximum declared and decoded live outputs.
    pub max_coins: u64,
    /// Maximum sum of decompressed script lengths across all coins.
    pub max_script_bytes: u64,
    /// Maximum live outputs in one transaction group.
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

/// Fully parsed state matching a compiled anchor, exposing the bare set for
/// offline inspection.
///
/// The commitment matched at read time only: `set` is public and mutable
/// through shared access, so this value is NOT a proof once handed out.
/// Activation consumes [`VerifiedCoreSnapshot`] from [`read_verified`]. Neither
/// proves genesis-to-base historical validation. There is no native-v4 trailer
/// in a Core file.
pub struct CoreSnapshot {
    /// Existing UTXO representation populated from decoded coins.
    pub set: UtxoSet,
    /// Parsed file header.
    pub metadata: SnapshotMetadata,
    /// Compiled trust anchor selected by network and base block hash.
    pub anchor: &'static AssumeUtxoData,
    /// Recomputed Bitcoin Core `hash_serialized_3`.
    pub hash_serialized: Hash256,
    /// Encoded bytes consumed, excluding the EOF probe.
    pub bytes_read: u64,
}

/// One owned UTXO set sealed with the commitment and statistics that were
/// derived from exactly its coins.
///
/// Fields are private and every constructor either recomputes the proof from
/// the owned set ([`Self::verify`]) or runs inside [`read_verified`] on records
/// whose commitment already matched a compiled anchor. No accessor exposes the
/// set: [`UtxoSet::replace_from`] mutates through a shared reference, so any
/// `&UtxoSet` would let a holder invalidate the proof. The only way out is
/// [`Self::into_parts`], which consumes the proof together with the set.
///
/// The proof is for the pinned identity recorded here; an activation owner must
/// still compare [`Self::base_hash`], [`Self::height`] and
/// [`Self::hash_serialized`] with its own compiled anchor.
pub struct VerifiedSnapshotState {
    set: UtxoSet,
    base_hash: Hash256,
    height: u32,
    hash_serialized: Hash256,
    stats: CoinStats,
}

/// Why an owned set could not be sealed as a [`VerifiedSnapshotState`].
#[derive(Debug, Error)]
pub enum StateVerifyError {
    /// Existing UTXO storage or commitment computation failed.
    #[error("snapshot UTXO state: {0}")]
    Utxo(#[from] UtxoError),
    /// The owned coins disagree with the anchor's commitment.
    #[error("snapshot commitment {actual} does not match pinned {expected}")]
    CommitmentMismatch {
        /// Anchor commitment.
        expected: Hash256,
        /// Commitment recomputed from the owned set.
        actual: Hash256,
    },
}

impl VerifiedSnapshotState {
    /// Recomputes the commitment and statistics of an owned set in one stable
    /// view and seals them only if the commitment equals `anchor`'s.
    ///
    /// This is the single verification for a set that arrived without proof
    /// (for example from the native v4 reader). The set is moved in, so nothing
    /// can change it between the traversal and the returned value. Statistics
    /// are scanned only after the commitment matched.
    ///
    /// # Errors
    ///
    /// Returns the storage/height error of the commitment traversal, or
    /// [`StateVerifyError::CommitmentMismatch`]; the set is dropped either way.
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

    /// Base block identity the commitment was verified for.
    #[must_use]
    pub const fn base_hash(&self) -> Hash256 {
        self.base_hash
    }

    /// Base height the commitment and statistics were computed at.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Verified Core `hash_serialized_3` of the sealed coins.
    #[must_use]
    pub const fn hash_serialized(&self) -> Hash256 {
        self.hash_serialized
    }

    /// Statistics of the sealed coins at [`Self::height`]; `tx_count` is zero
    /// until the activation owner installs the pinned transaction count.
    #[must_use]
    pub const fn stats(&self) -> &CoinStats {
        &self.stats
    }

    /// Ends the proof and yields the set with its statistics for installation.
    #[must_use]
    pub fn into_parts(self) -> (UtxoSet, CoinStats) {
        (self.set, self.stats)
    }
}

/// A decoded Core file whose set is sealed in a [`VerifiedSnapshotState`].
pub struct VerifiedCoreSnapshot {
    /// Parsed file header.
    pub metadata: SnapshotMetadata,
    /// Compiled trust anchor selected by network and base block hash.
    pub anchor: &'static AssumeUtxoData,
    /// Encoded bytes consumed, excluding the EOF probe.
    pub bytes_read: u64,
    state: VerifiedSnapshotState,
}

impl VerifiedCoreSnapshot {
    /// Proof carried from the reader to activation.
    #[must_use]
    pub const fn state(&self) -> &VerifiedSnapshotState {
        &self.state
    }

    /// Moves the proof out for activation.
    #[must_use]
    pub fn into_state(self) -> VerifiedSnapshotState {
        self.state
    }
}

/// Typed failures shared by offline tools and node import.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// The fixed header or a coin field ended prematurely.
    #[error("snapshot truncated at byte {offset}")]
    Truncated {
        /// Number of bytes successfully consumed before EOF.
        offset: u64,
    },
    /// An underlying input operation failed.
    #[error("snapshot input failed: {0}")]
    Io(#[from] io::Error),
    /// Magic does not identify a Core portable snapshot.
    #[error("invalid Bitcoin Core snapshot magic")]
    InvalidMagic,
    /// Header version is not supported.
    #[error("unsupported Bitcoin Core snapshot version {version}")]
    UnsupportedVersion {
        /// Observed version.
        version: u16,
    },
    /// File network differs from the selected network.
    #[error("snapshot network magic {actual:02x?} does not match {expected:02x?}")]
    WrongNetwork {
        /// Selected network magic.
        expected: [u8; 4],
        /// File network magic.
        actual: [u8; 4],
    },
    /// No compiled anchor trusts this base on the selected network.
    #[error("snapshot base {base_hash} is not pinned for {network:?}")]
    UnsupportedAnchor {
        /// Selected consensus network.
        network: Network,
        /// File base block identity.
        base_hash: Hash256,
    },
    /// A configured budget would be exceeded.
    #[error("snapshot {resource} budget exceeded: {actual} > {limit}")]
    LimitExceeded {
        /// Resource being bounded.
        resource: &'static str,
        /// Attempted amount.
        actual: u64,
        /// Configured maximum.
        limit: u64,
    },
    /// A `CompactSize` uses a non-minimal spelling.
    #[error("snapshot CompactSize is noncanonical")]
    NonCanonicalCompactSize,
    /// A `CompactSize` exceeds Core's default input limit.
    #[error("snapshot CompactSize value {value} exceeds the Core limit")]
    CompactSizeTooLarge {
        /// Decoded value.
        value: u64,
    },
    /// Core's subtract-one base-128 integer overflowed its field.
    #[error("snapshot Core VARINT overflows its field")]
    VarIntOverflow,
    /// A txid group contains no outputs.
    #[error("snapshot contains an empty transaction group")]
    EmptyGroup,
    /// A group claims more coins than remain in the header count.
    #[error("snapshot group declares {group} coins with only {remaining} remaining")]
    CoinCountMismatch {
        /// Group's declared output count.
        group: u64,
        /// Remaining declared file coins.
        remaining: u64,
    },
    /// Declared coins count does not match the actual number of written coins.
    #[error("snapshot declared {declared} coins, wrote {actual}")]
    DeclaredCoinCountMismatch {
        /// Declared count.
        declared: u64,
        /// Actual written count.
        actual: u64,
    },
    /// The snapshot write or read was interrupted.
    #[error("snapshot operation interrupted")]
    Interrupted,
    /// Core emits exactly one group per txid in bytewise order.
    #[error("snapshot transaction groups are duplicated or out of Core byte order")]
    TransactionOrder,
    /// A group repeats an output index.
    #[error("snapshot repeats output index {vout}")]
    DuplicateOutpoint {
        /// Repeated index in the current transaction.
        vout: u32,
    },
    /// An output index cannot identify a live coin.
    #[error("snapshot output index {vout} is invalid")]
    InvalidOutpoint {
        /// Invalid index.
        vout: u64,
    },
    /// A coin claims creation after the trusted snapshot base.
    #[error("snapshot coin height {height} exceeds base height {base_height}")]
    InvalidHeight {
        /// Coin creation height.
        height: u32,
        /// Compiled base height.
        base_height: u32,
    },
    /// Amount decompression overflowed or exceeded `MAX_MONEY`.
    #[error("snapshot compressed amount {compressed} is out of range")]
    InvalidAmount {
        /// Compressed amount.
        compressed: u64,
    },
    /// Raw or decompressed script exceeds the Core script-size limit.
    #[error("snapshot script length {length} exceeds 10000 bytes")]
    InvalidScriptLength {
        /// Decoded script length.
        length: u64,
    },
    /// An uncompressed P2PK encoding does not reconstruct a curve point.
    #[error("snapshot uncompressed P2PK encoding has an invalid curve point")]
    InvalidPublicKey,
    /// The complete declared set is followed by more data.
    #[error("snapshot has trailing bytes")]
    TrailingBytes,
    /// Existing UTXO storage or commitment validation failed.
    #[error("snapshot UTXO state: {0}")]
    Utxo(#[from] UtxoError),
    /// Decoded coins disagree with the compiled trust anchor.
    #[error("snapshot commitment {actual} does not match pinned {expected}")]
    CommitmentMismatch {
        /// Compiled commitment.
        expected: Hash256,
        /// Recomputed commitment.
        actual: Hash256,
    },
}

/// Reads only the fixed 51-byte Core v2 header.
///
/// Network identity and anchor support are not checked here. The result must
/// never be described as full content verification.
pub fn read_metadata(reader: &mut impl Read) -> Result<SnapshotMetadata, SnapshotError> {
    Decoder::new(reader, HEADER_BYTES).metadata()
}

/// Decodes an entire Core v2 file and verifies its compiled state commitment.
///
/// No file is modified. Unknown anchors and oversized declared counts are
/// rejected before allocating records. Core-generated groups are checked in
/// byte order and each group's vouts are sorted for duplicate detection and the
/// shared commitment serializer. Only a matching compiled commitment allows
/// record payloads to move into the UTXO hash table. Input bytes and decoded
/// resources are bounded independently of untrusted counts.
pub fn read_and_verify(
    reader: &mut impl Read,
    network: Network,
    limits: SnapshotLimits,
) -> Result<CoreSnapshot, SnapshotError> {
    let authenticated = authenticate(reader, network, limits)?;
    // The only inputs reaching the identity-hashed UTXO table now belong to
    // the compiled state. Forged colliding txids never reach insertion.
    let set = UtxoSet::new();
    for record in authenticated.records {
        set.insert_snapshot_record(record);
    }
    Ok(CoreSnapshot {
        set,
        metadata: authenticated.metadata,
        anchor: authenticated.anchor,
        hash_serialized: authenticated.hash_serialized,
        bytes_read: authenticated.bytes_read,
    })
}

/// Decodes an entire Core v2 file like [`read_and_verify`] and seals the result
/// for activation.
///
/// The statistics (including `MuHash`) are folded from the authenticated staged
/// records while they move into the UTXO table, so activation needs neither a
/// second commitment pass nor a statistics scan over the table. Statistics are
/// never computed for a file whose commitment did not match.
///
/// # Errors
///
/// The same typed failures as [`read_and_verify`].
pub fn read_verified(
    reader: &mut impl Read,
    network: Network,
    limits: SnapshotLimits,
) -> Result<VerifiedCoreSnapshot, SnapshotError> {
    let authenticated = authenticate(reader, network, limits)?;
    let anchor = authenticated.anchor;
    let mut accumulator = CoinStatsAccumulator::with_parallel_muhash(anchor.height);
    let set = UtxoSet::new();
    for record in authenticated.records {
        let txid = record.txid();
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
        set.insert_snapshot_record(record);
    }
    Ok(VerifiedCoreSnapshot {
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
    })
}

/// Staged records whose commitment matched a compiled anchor; no hash table yet.
struct Authenticated {
    records: Vec<UtxoRecord>,
    metadata: SnapshotMetadata,
    anchor: &'static AssumeUtxoData,
    hash_serialized: Hash256,
    bytes_read: u64,
}

fn authenticate(
    reader: &mut impl Read,
    network: Network,
    limits: SnapshotLimits,
) -> Result<Authenticated, SnapshotError> {
    let mut decoder = Decoder::new(reader, limits.max_file_bytes);
    let metadata = decoder.metadata()?;
    if metadata.network_magic != network.magic() {
        return Err(SnapshotError::WrongNetwork {
            expected: network.magic(),
            actual: metadata.network_magic,
        });
    }
    let anchor = network
        .assume_utxo_for_hash(metadata.base_block_hash)
        .ok_or(SnapshotError::UnsupportedAnchor {
            network,
            base_hash: metadata.base_block_hash,
        })?;
    let (records, hash_serialized) = decoder.coins(metadata.coins_count, anchor.height, limits)?;
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

/// Report returned upon successful export of a Bitcoin Core v2 snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreV2WriteReport {
    /// Total bytes written to the sink, including header and coin records.
    pub bytes: u64,
    /// Total number of coins written.
    pub coins: u64,
    /// Computed `hash_serialized_3` state commitment matching Bitcoin Core.
    pub txoutset_hash: Hash256,
}

/// Writes a complete Bitcoin Core portable snapshot v2 into `writer`.
///
/// Emits the fixed 51-byte header, followed by ascending internal txid-LE groups
/// across shards 0..=255. Within each shard, entries follow the same canonical
/// Core ordering as [`hash_serialized_3_stable_inner`]. Each group serializes:
/// - 32-byte internal txid (LE)
/// - `CompactSize` output count (group size)
/// - Per output:
///   - `CompactSize` `vout`
///   - Core VARINT `(height << 1) | (coinbase as u32)`
///   - Core VARINT `compress_amount(value)`
///   - Compressed scriptPubKey (or raw length + 6 followed by raw script)
///
/// In the same pass, updates [`SerializedUtxoHasher`] with each coin in canonical
/// txid/vout order, computing the exact `hash_serialized_3` commitment matching Core.
///
/// Polls `should_stop()` every 5,000 coins and immediately aborts with
/// [`SnapshotError::Interrupted`]. Fails with [`SnapshotError::DeclaredCoinCountMismatch`]
/// if the written coins count does not match `coins_count`.
pub fn write_core_v2<W: Write + ?Sized>(
    view: &UtxoSetView<'_>,
    network: Network,
    base_hash: Hash256,
    base_height: u32,
    coins_count: u64,
    writer: &mut W,
    should_stop: &dyn Fn() -> bool,
) -> Result<CoreV2WriteReport, SnapshotError> {
    if should_stop() {
        return Err(SnapshotError::Interrupted);
    }

    // 1. Fixed 51-byte Core v2 header:
    // MAGIC (5) + VERSION (2) + network magic (4) + base block hash (32) + coins count (8)
    writer.write_all(&MAGIC)?;
    writer.write_all(&VERSION.to_le_bytes())?;
    writer.write_all(&network.magic())?;
    writer.write_all(&base_hash.to_le_bytes())?;
    writer.write_all(&coins_count.to_le_bytes())?;

    let mut total_bytes: u64 = HEADER_BYTES;
    let mut coins_written: u64 = 0;
    let mut last_polled_coins: u64 = 0;
    let mut commitment = SerializedUtxoHasher::new();
    let mut varint_buf = Vec::with_capacity(10);

    for shard_idx in 0_u8..=u8::MAX {
        view.shard(usize::from(shard_idx)).with_table(|table| {
            let mut records: Vec<&UtxoRecord> = table.table.iter().collect();
            records.sort_unstable_by(|left, right| {
                left.txid().to_le_bytes().cmp(&right.txid().to_le_bytes())
            });

            for record in records {
                let txid_bytes = record.txid().to_le_bytes();
                let mut outputs: Vec<crate::record::OneUtxoOut<'_>> = record.outputs().collect();
                if outputs.is_empty() {
                    continue;
                }
                outputs.sort_unstable_by_key(|output| output.vout);

                let group_count =
                    u64::try_from(outputs.len()).map_err(|_| SnapshotError::LimitExceeded {
                        resource: "coins per txid",
                        actual: u64::MAX,
                        limit: u64::from(u32::MAX),
                    })?;

                // Txid (32 bytes)
                writer.write_all(&txid_bytes)?;
                total_bytes = total_bytes
                    .checked_add(32)
                    .ok_or(SnapshotError::VarIntOverflow)?;

                // CompactSize group count
                let group_encoded = varint::encode(group_count);
                writer.write_all(group_encoded.as_slice())?;
                total_bytes = total_bytes
                    .checked_add(u64::try_from(group_encoded.len()).unwrap_or(0))
                    .ok_or(SnapshotError::VarIntOverflow)?;

                // Per-output serialization
                for output in outputs {
                    let entry_bytes =
                        write_output_entry(writer, &output, base_height, &mut varint_buf)?;
                    total_bytes = total_bytes
                        .checked_add(entry_bytes)
                        .ok_or(SnapshotError::VarIntOverflow)?;

                    // Accumulate state commitment
                    commitment.add(txid_bytes, output, Some(base_height))?;

                    coins_written = coins_written
                        .checked_add(1)
                        .ok_or(SnapshotError::VarIntOverflow)?;

                    // Check declared coins count ceiling
                    if coins_written > coins_count {
                        return Err(SnapshotError::DeclaredCoinCountMismatch {
                            declared: coins_count,
                            actual: coins_written,
                        });
                    }

                    // Poll should_stop every 5,000 coins
                    if coins_written.saturating_sub(last_polled_coins) >= 5000 {
                        last_polled_coins = coins_written;
                        if should_stop() {
                            return Err(SnapshotError::Interrupted);
                        }
                    }
                }
            }
            Ok::<(), SnapshotError>(())
        })?;
    }

    if coins_written != coins_count {
        return Err(SnapshotError::DeclaredCoinCountMismatch {
            declared: coins_count,
            actual: coins_written,
        });
    }

    Ok(CoreV2WriteReport {
        bytes: total_bytes,
        coins: coins_written,
        txoutset_hash: commitment.finish(),
    })
}

fn write_output_entry<W: Write + ?Sized>(
    writer: &mut W,
    output: &OneUtxoOut<'_>,
    base_height: u32,
    varint_buf: &mut Vec<u8>,
) -> Result<u64, SnapshotError> {
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

    // Core snapshot v2 format requires the packed height/coinbase code to be
    // representable in a 32-bit field. If bit 31 of height is set (height >= 0x8000_0000),
    // (height << 1) cannot fit in u32, causing high-bit loss in commitment hashing
    // and incompatible wire encoding rejected by Core readers.
    let raw_code = (u64::from(output.height) << 1) | u64::from(output.coinbase);
    let code = u32::try_from(raw_code).map_err(|_| SnapshotError::VarIntOverflow)?;

    let mut written: u64 = 0;

    // CompactSize vout
    let vout_encoded = varint::encode(u64::from(output.vout));
    writer.write_all(vout_encoded.as_slice())?;
    written = written
        .checked_add(u64::try_from(vout_encoded.len()).unwrap_or(0))
        .ok_or(SnapshotError::VarIntOverflow)?;

    // Core VARINT height/coinbase: (height << 1) | (coinbase as u32)
    varint_buf.clear();
    crate::compress::write_core_varint(u64::from(code), varint_buf);
    writer.write_all(varint_buf)?;
    written = written
        .checked_add(u64::try_from(varint_buf.len()).unwrap_or(0))
        .ok_or(SnapshotError::VarIntOverflow)?;

    // Core VARINT compressed amount
    let compressed_amount = crate::compress::compress_amount(output.value)?;
    varint_buf.clear();
    crate::compress::write_core_varint(compressed_amount, varint_buf);
    writer.write_all(varint_buf)?;
    written = written
        .checked_add(u64::try_from(varint_buf.len()).unwrap_or(0))
        .ok_or(SnapshotError::VarIntOverflow)?;

    // Compressed script
    if let Some((script_code, payload)) = crate::compress::compress_script(output.script_pubkey) {
        varint_buf.clear();
        crate::compress::write_core_varint(script_code, varint_buf);
        writer.write_all(varint_buf)?;
        written = written
            .checked_add(u64::try_from(varint_buf.len()).unwrap_or(0))
            .ok_or(SnapshotError::VarIntOverflow)?;

        writer.write_all(payload)?;
        written = written
            .checked_add(u64::try_from(payload.len()).unwrap_or(0))
            .ok_or(SnapshotError::VarIntOverflow)?;
    } else {
        let script_len = output.script_pubkey.len();
        if script_len > 10_000 {
            return Err(SnapshotError::InvalidScriptLength {
                length: u64::try_from(script_len).unwrap_or(u64::MAX),
            });
        }
        let script_code = u64::try_from(script_len)
            .map_err(|_| SnapshotError::VarIntOverflow)?
            .checked_add(6)
            .ok_or(SnapshotError::VarIntOverflow)?;
        varint_buf.clear();
        crate::compress::write_core_varint(script_code, varint_buf);
        writer.write_all(varint_buf)?;
        written = written
            .checked_add(u64::try_from(varint_buf.len()).unwrap_or(0))
            .ok_or(SnapshotError::VarIntOverflow)?;

        writer.write_all(output.script_pubkey)?;
        written = written
            .checked_add(u64::try_from(output.script_pubkey.len()).unwrap_or(0))
            .ok_or(SnapshotError::VarIntOverflow)?;
    }

    Ok(written)
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
                    // Read returns at most the remaining slice length; its
                    // full end position was checked against max_bytes above.
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
        // A u64 needs at most ten bytes. Core's continuation adds one after
        // each seven-bit group; this is deliberately NOT record LEB128.
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
                // Core preserves even non-curve compressed pubkey bytes here.
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

    fn coins(
        &mut self,
        count: u64,
        base_height: u32,
        limits: SnapshotLimits,
    ) -> Result<(Vec<UtxoRecord>, Hash256), SnapshotError> {
        check_limit("coins", count, limits.max_coins)?;
        check_limit(
            "addressable coins",
            count,
            u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        )?;
        // Temporary transaction staging holds the existing record payloads,
        // without a hash table or a second coin representation. The vector
        // grows only after a complete bounded group has arrived.
        let mut records = Vec::new();
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
                let amount = crate::compress::decompress_amount(compressed)
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
            // Core's disk-key order is not a numeric-vout contract. Sorting
            // also detects duplicates without hashing untrusted indices.
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
            records.push(record);
            remaining -= group;
        }
        Ok((records, commitment.finish()))
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
mod tests;

// Proof-carrying state: the folded statistics replace a scan of the table, so
// they must equal one; the proofless constructor must refuse any change.
#[cfg(test)]
mod sealed_state_tests {
    use std::io::Cursor;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const CORE: &[u8] = include_bytes!("../tests/fixtures/core-v2/core200.dat");

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
        let mutated = bare()?;
        // Shared-reference mutation is exactly what the sealed type forbids.
        mutated.set.replace_from(UtxoSet::new());
        assert!(matches!(
            VerifiedSnapshotState::verify(mutated.set, anchor),
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
        let last = forged.last_mut().ok_or("empty fixture")?;
        *last ^= 1;
        let before = crate::set::SNAPSHOT_INSERTIONS.with(std::cell::Cell::get);
        assert!(matches!(
            read_verified(
                &mut Cursor::new(&forged),
                Network::Regtest,
                SnapshotLimits::default()
            ),
            Err(SnapshotError::CommitmentMismatch { .. })
        ));
        assert_eq!(
            crate::set::SNAPSHOT_INSERTIONS.with(std::cell::Cell::get),
            before
        );
        drop(sealed()?);
        assert_eq!(
            crate::set::SNAPSHOT_INSERTIONS.with(std::cell::Cell::get),
            before + 200
        );
        Ok(())
    }
}
