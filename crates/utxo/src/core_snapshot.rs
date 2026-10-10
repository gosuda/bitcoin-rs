//! Bitcoin Core portable snapshot v2 input.
//!
//! The header is untrusted metadata. Full loading resolves a compiled network
//! anchor, checks the commitment of staged existing records, and only then
//! installs them into the existing UTXO set.
//! Native bitcoin-rs v4 checkpoint serialization is a separate format.

use std::io::{self, Read};

use bitcoin_rs_primitives::{AssumeUtxoData, Hash256, Network, varint};
use thiserror::Error;

use crate::{
    UtxoError, UtxoSet,
    record::{OwnedUtxoOut, UtxoRecord},
    snapshot::SerializedUtxoHasher,
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

/// Fully parsed state matching a compiled anchor.
///
/// This proves pinned-state consistency, not genesis-to-base historical
/// validation. Consumers must preserve the existing activation owner's checks
/// when installing the set. There is no native-v4 trailer in a Core file.
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
    Io(#[source] io::Error),
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
    // The only inputs reaching the identity-hashed UTXO table now belong to
    // the compiled state. Forged colliding txids never reach insertion.
    let set = UtxoSet::new();
    for record in records {
        set.insert_snapshot_record(record);
    }
    Ok(CoreSnapshot {
        set,
        metadata,
        anchor,
        hash_serialized,
        bytes_read: decoder.consumed,
    })
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
