//! Framed, checksummed chainstate journal records.

use bitcoin_rs_primitives::{ConsensusDecode, ConsensusEncode, Hash256, OutPoint, TxOut};
use thiserror::Error;

const MAGIC: [u8; 4] = *b"JRNL";
const VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = MAGIC.len() + 1 + core::mem::size_of::<u32>();
const FRAME_TRAILER_LEN: usize = core::mem::size_of::<u32>();
const MAX_PAYLOAD_LEN: usize = 256 * 1024 * 1024;
const MAX_MUTATIONS: u32 = 4_000_000;

/// A complete coin, including the fields required by `CoinStats`' `MuHash` preimage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Coin {
    /// Transaction output identifier.
    pub(crate) outpoint: OutPoint,
    /// Output value and script.
    pub(crate) txout: TxOut,
    /// Height at which this output was created.
    pub(crate) height: u32,
    /// Whether the creating transaction was coinbase.
    pub(crate) coinbase: bool,
}

/// An ordered in-block chainstate mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Mutation {
    /// Add a newly created output.
    Create { coin: Coin },
    /// Remove a spent output.
    Spend { coin: Coin },
    /// Replace a BIP30 duplicate-txid output.
    Overwrite { old_coin: Coin, new_coin: Coin },
}

/// Block metadata carried alongside the mutation list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlockMeta {
    /// Height of the block represented by this record.
    pub(crate) height: u32,
    /// Hash of the block represented by this record.
    pub(crate) block_hash: [u8; 32],
    /// Hash of the preceding block.
    pub(crate) prev_hash: [u8; 32],
    /// Number of transactions in the block.
    pub(crate) block_tx_count: u64,
    /// `CoinStats` height delta applied by the block.
    pub(crate) coin_stats_height_delta: i64,
}

/// One framed journal record for one applied block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JournalRecord {
    /// Height of the block represented by this record.
    pub(crate) height: u32,
    /// Hash of the block represented by this record.
    pub(crate) block_hash: [u8; 32],
    /// Hash of the preceding block.
    pub(crate) prev_hash: [u8; 32],
    /// Number of transactions in the block.
    pub(crate) block_tx_count: u64,
    /// `CoinStats` height delta applied by the block.
    pub(crate) coin_stats_height_delta: i64,
    /// The block's full 80-byte consensus header. Boot replay rebuilds the
    /// checkpoint→head header chain in the `BlockTree` from these, which is what
    /// makes the post-replay `TipSnapshot` (`NodeId` + `chainwork`) reconstructible.
    pub(crate) raw_header: [u8; 80],
    /// Mutations in exact commit order.
    pub(crate) mutations: Vec<Mutation>,
}

impl JournalRecord {
    /// Returns the block metadata portion of this record.
    pub(crate) const fn block_meta(&self) -> BlockMeta {
        BlockMeta {
            height: self.height,
            block_hash: self.block_hash,
            prev_hash: self.prev_hash,
            block_tx_count: self.block_tx_count,
            coin_stats_height_delta: self.coin_stats_height_delta,
        }
    }
}

/// Errors returned when a journal frame cannot be decoded.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum JournalRecordError {
    /// The four-byte record marker did not match.
    #[error("chainstate journal record has bad magic")]
    BadMagic,
    /// The record version is not supported.
    #[error("unsupported chainstate journal record version {found}, expected {expected}")]
    BadVersion { found: u8, expected: u8 },
    /// The payload checksum did not match.
    #[error(
        "chainstate journal record checksum mismatch: expected {expected:#010x}, found {found:#010x}"
    )]
    CrcMismatch { expected: u32, found: u32 },
    /// The frame ended before a complete field was available.
    #[error("chainstate journal record ended unexpectedly")]
    UnexpectedEof,
    /// The frame was structurally invalid.
    #[error("malformed chainstate journal record payload")]
    MalformedPayload,
}

/// Encodes a journal record with magic, version, length, payload, and CRC32C.
#[must_use]
pub(crate) fn encode_record(record: &JournalRecord) -> Vec<u8> {
    let mut payload = Vec::new();
    put_u32(&mut payload, record.height);
    payload.extend_from_slice(&record.block_hash);
    payload.extend_from_slice(&record.prev_hash);
    put_u64(&mut payload, record.block_tx_count);
    put_i64(&mut payload, record.coin_stats_height_delta);
    payload.extend_from_slice(&record.raw_header);
    put_u32(&mut payload, u32_len(record.mutations.len()));
    for mutation in &record.mutations {
        match mutation {
            Mutation::Create { coin } => {
                payload.push(0);
                put_coin(&mut payload, coin);
            }
            Mutation::Spend { coin } => {
                payload.push(1);
                put_coin(&mut payload, coin);
            }
            Mutation::Overwrite { old_coin, new_coin } => {
                payload.push(2);
                put_coin(&mut payload, old_coin);
                put_coin(&mut payload, new_coin);
            }
        }
    }

    let payload_len = u32_len(payload.len());
    let mut framed = Vec::with_capacity(FRAME_HEADER_LEN + payload.len() + FRAME_TRAILER_LEN);
    framed.extend_from_slice(&MAGIC);
    framed.push(VERSION);
    put_u32(&mut framed, payload_len);
    framed.extend_from_slice(&payload);
    put_u32(&mut framed, crc32c(&payload));
    framed
}

/// Decodes and validates one complete journal record.
pub(crate) fn decode_record(bytes: &[u8]) -> Result<JournalRecord, JournalRecordError> {
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(JournalRecordError::UnexpectedEof);
    }
    if bytes[..MAGIC.len()] != MAGIC {
        return Err(JournalRecordError::BadMagic);
    }
    if bytes[MAGIC.len()] != VERSION {
        return Err(JournalRecordError::BadVersion {
            found: bytes[MAGIC.len()],
            expected: VERSION,
        });
    }

    let payload_len = usize::try_from(u32::from_le_bytes(
        bytes[MAGIC.len() + 1..FRAME_HEADER_LEN]
            .try_into()
            .map_err(|_| JournalRecordError::UnexpectedEof)?,
    ))
    .map_err(|_| JournalRecordError::MalformedPayload)?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(JournalRecordError::MalformedPayload);
    }
    let total_len = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(FRAME_TRAILER_LEN))
        .ok_or(JournalRecordError::MalformedPayload)?;
    if bytes.len() < total_len {
        return Err(JournalRecordError::UnexpectedEof);
    }
    if bytes.len() != total_len {
        return Err(JournalRecordError::MalformedPayload);
    }

    let payload = &bytes[FRAME_HEADER_LEN..FRAME_HEADER_LEN + payload_len];
    let found_crc = u32::from_le_bytes(
        bytes[FRAME_HEADER_LEN + payload_len..total_len]
            .try_into()
            .map_err(|_| JournalRecordError::UnexpectedEof)?,
    );
    let expected_crc = crc32c(payload);
    if found_crc != expected_crc {
        return Err(JournalRecordError::CrcMismatch {
            expected: expected_crc,
            found: found_crc,
        });
    }
    decode_payload(payload)
}

fn decode_payload(payload: &[u8]) -> Result<JournalRecord, JournalRecordError> {
    let mut cursor = Cursor::new(payload);
    let height = cursor.u32()?;
    let block_hash = cursor.array::<32>()?;
    let prev_hash = cursor.array::<32>()?;
    let block_tx_count = cursor.u64()?;
    let coin_stats_height_delta = cursor.i64()?;
    let raw_header = cursor.array::<80>()?;
    let mutation_count = cursor.u32()?;
    if mutation_count > MAX_MUTATIONS {
        return Err(JournalRecordError::MalformedPayload);
    }
    let mut mutations = Vec::with_capacity(usize::try_from(mutation_count).unwrap_or(0).min(4096));
    for _ in 0..mutation_count {
        let mutation = match cursor.byte()? {
            0 => Mutation::Create {
                coin: cursor.coin()?,
            },
            1 => Mutation::Spend {
                coin: cursor.coin()?,
            },
            2 => Mutation::Overwrite {
                old_coin: cursor.coin()?,
                new_coin: cursor.coin()?,
            },
            _ => return Err(JournalRecordError::MalformedPayload),
        };
        mutations.push(mutation);
    }
    if cursor.remaining() != 0 {
        return Err(JournalRecordError::MalformedPayload);
    }
    Ok(JournalRecord {
        height,
        block_hash,
        prev_hash,
        block_tx_count,
        coin_stats_height_delta,
        raw_header,
        mutations,
    })
}

fn put_coin(out: &mut Vec<u8>, coin: &Coin) {
    out.extend_from_slice(coin.outpoint.txid.as_bytes());
    put_u32(out, coin.outpoint.vout);
    let _ = coin.txout.consensus_encode(out);
    put_u32(out, coin.height);
    out.push(u8::from(coin.coinbase));
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u32_len(value: usize) -> u32 {
    debug_assert!(u32::try_from(value).is_ok());
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], JournalRecordError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(JournalRecordError::UnexpectedEof)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(JournalRecordError::UnexpectedEof)?;
        self.offset = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], JournalRecordError> {
        self.take(N)?
            .try_into()
            .map_err(|_| JournalRecordError::UnexpectedEof)
    }

    fn byte(&mut self) -> Result<u8, JournalRecordError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, JournalRecordError> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, JournalRecordError> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }

    fn i64(&mut self) -> Result<i64, JournalRecordError> {
        Ok(i64::from_le_bytes(self.array::<8>()?))
    }

    fn coin(&mut self) -> Result<Coin, JournalRecordError> {
        let txid = Hash256::from_le_bytes(&self.array::<32>()?);
        let vout = self.u32()?;
        let rest = self
            .bytes
            .get(self.offset..)
            .ok_or(JournalRecordError::UnexpectedEof)?;
        let before = rest.len();
        let mut reader = rest;
        let txout = TxOut::consensus_decode(&mut reader)
            .map_err(|_| JournalRecordError::MalformedPayload)?;
        let consumed = before
            .checked_sub(reader.len())
            .ok_or(JournalRecordError::MalformedPayload)?;
        if consumed == 0 {
            return Err(JournalRecordError::MalformedPayload);
        }
        self.offset = self
            .offset
            .checked_add(consumed)
            .ok_or(JournalRecordError::MalformedPayload)?;
        let height = self.u32()?;
        let coinbase = match self.byte()? {
            0 => false,
            1 => true,
            _ => return Err(JournalRecordError::MalformedPayload),
        };
        Ok(Coin {
            outpoint: OutPoint::new(txid.into(), vout),
            txout,
            height,
            coinbase,
        })
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BlockMeta, Coin, JournalRecord, JournalRecordError, Mutation, decode_record, encode_record,
    };
    use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
    use proptest::prelude::*;

    fn coin(seed: u8, height: u32, coinbase: bool) -> Coin {
        Coin {
            outpoint: OutPoint::new(Txid(Hash256::from_le_bytes(&[seed; 32])), u32::from(seed)),
            txout: TxOut {
                value: u64::from(seed) * 1_000,
                script_pubkey: vec![0x51, seed],
            },
            height,
            coinbase,
        }
    }

    /// Builds a deterministic 80-byte header whose hash equals the given hash.
    fn header_bytes(hash: [u8; 32]) -> [u8; 80] {
        // version | prev | merkle | time | bits | nonce — content is opaque to
        // the codec (it only frames bytes), but keep it hash-derived so tests
        // can assert the field survives the roundtrip positionally.
        let mut header = [0_u8; 80];
        header[0..4].copy_from_slice(&1_i32.to_le_bytes());
        header[36..68].copy_from_slice(&hash);
        header
    }

    fn sample() -> JournalRecord {
        JournalRecord {
            height: 42,
            block_hash: [9; 32],
            prev_hash: [8; 32],
            block_tx_count: 70_000,
            coin_stats_height_delta: -1,
            raw_header: header_bytes(42),
            mutations: vec![
                Mutation::Create {
                    coin: coin(1, 42, true),
                },
                Mutation::Spend {
                    coin: coin(2, 11, false),
                },
                Mutation::Overwrite {
                    old_coin: coin(3, 7, false),
                    new_coin: coin(4, 42, false),
                },
            ],
        }
    }

    #[test]
    fn round_trips_genesis_and_all_mutation_kinds() {
        let genesis = JournalRecord {
            height: 0,
            block_hash: [0; 32],
            prev_hash: [0; 32],
            block_tx_count: 1,
            coin_stats_height_delta: 0,
            raw_header: header_bytes([0; 32]),
            mutations: Vec::new(),
        };
        for record in [genesis, sample()] {
            assert_eq!(decode_record(&encode_record(&record)), Ok(record));
        }
        let meta = sample().block_meta();
        assert_eq!(
            meta,
            BlockMeta {
                height: 42,
                block_hash: [9; 32],
                prev_hash: [8; 32],
                block_tx_count: 70_000,
                coin_stats_height_delta: -1
            }
        );
    }

    #[test]
    fn every_single_byte_corruption_is_rejected() {
        let bytes = encode_record(&sample());
        for index in 0..bytes.len() {
            let mut corrupted = bytes.clone();
            corrupted[index] ^= 1;
            assert!(
                decode_record(&corrupted).is_err(),
                "byte {index} was accepted"
            );
        }
    }

    #[test]
    fn every_truncated_prefix_is_rejected() {
        let bytes = encode_record(&sample());
        for length in 0..bytes.len() {
            assert!(
                decode_record(&bytes[..length]).is_err(),
                "prefix {length} was accepted"
            );
        }
        assert!(decode_record(&bytes).is_ok());
    }

    #[test]
    fn bad_magic_and_version_are_rejected() {
        let bytes = encode_record(&sample());
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert_eq!(decode_record(&bad_magic), Err(JournalRecordError::BadMagic));
        let mut bad_version = bytes;
        bad_version[4] = 2;
        assert!(matches!(
            decode_record(&bad_version),
            Err(JournalRecordError::BadVersion { .. })
        ));
    }

    fn arb_coin() -> impl Strategy<Value = Coin> {
        (any::<u8>(), any::<u32>(), any::<bool>(), 0..12_usize).prop_map(
            |(seed, height, coinbase, script_len)| Coin {
                outpoint: OutPoint::new(Txid(Hash256::from_le_bytes(&[seed; 32])), u32::from(seed)),
                txout: TxOut {
                    value: u64::from(seed),
                    script_pubkey: vec![seed; script_len],
                },
                height,
                coinbase,
            },
        )
    }

    fn arb_mutation() -> impl Strategy<Value = Mutation> {
        prop_oneof![
            arb_coin().prop_map(|coin| Mutation::Create { coin }),
            arb_coin().prop_map(|coin| Mutation::Spend { coin }),
            (arb_coin(), arb_coin())
                .prop_map(|(old_coin, new_coin)| Mutation::Overwrite { old_coin, new_coin }),
        ]
    }

    proptest! {
        #[test]
        fn arbitrary_mutation_lists_round_trip(
            height in any::<u32>(),
            block_hash in any::<[u8; 32]>(),
            prev_hash in any::<[u8; 32]>(),
            block_tx_count in any::<u64>(),
            coin_stats_height_delta in any::<i64>(),
            mutations in prop::collection::vec(arb_mutation(), 0..16),
        ) {
            let raw_header = header_bytes(block_hash);
            let record = JournalRecord { height, block_hash, prev_hash, block_tx_count, coin_stats_height_delta, raw_header, mutations };
            prop_assert_eq!(decode_record(&encode_record(&record)), Ok(record));
        }
    }
}
