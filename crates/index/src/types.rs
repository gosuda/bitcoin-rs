use bitcoin_rs_primitives::{Hash256, OutPoint, Txid, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Number of bytes retained from hashes in index rows.
pub const HASH_PREFIX_LEN: usize = 8;
/// Number of bytes used for big-endian block heights in index rows.
///
/// Big-endian makes lexicographic KV order match numeric height order within
/// one prefix, so LSM prefix compression and chronological scans share the
/// same key layout.
pub const HEIGHT_SIZE: usize = 4;
/// Serialized byte length of a hash-prefix row.
pub const HASH_PREFIX_ROW_SIZE: usize = HASH_PREFIX_LEN + HEIGHT_SIZE;
/// Serialized byte length of a Bitcoin block header.
pub const HEADER_ROW_SIZE: usize = 80;
/// Byte width of a [`HeaderRow`] identity key: double-SHA256 of the header.
pub const HEADER_KEY_SIZE: usize = 32;
/// Exclusive upper bound of a packed 24-bit field (`offset`, `length`, or live `vout`).
pub const U24_MAX: u32 = 0x00FF_FFFF;

/// Encodes a block height so lexicographic byte order matches numeric order.
#[must_use]
pub const fn encode_height(height: u32) -> [u8; HEIGHT_SIZE] {
    height.to_be_bytes()
}

/// Decodes a block height stored by [`encode_height`].
#[must_use]
pub const fn decode_height(bytes: [u8; HEIGHT_SIZE]) -> u32 {
    u32::from_be_bytes(bytes)
}

const fn encode_u24_le(value: u32) -> [u8; 3] {
    let bytes = value.to_le_bytes();
    [bytes[0], bytes[1], bytes[2]]
}

const fn decode_u24_le(bytes: [u8; 3]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

/// Prefix used as the seek key for electrs-style hash-prefix rows.
pub type HashPrefix = [u8; HASH_PREFIX_LEN];

/// A hash-prefix row: eight prefix bytes followed by a big-endian height.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
)]
#[repr(C)]
pub struct HashPrefixRow {
    /// The first eight bytes of the indexed hash-derived key.
    pub prefix: HashPrefix,
    /// The transaction-confirming block height, encoded big-endian.
    pub height: [u8; HEIGHT_SIZE],
}

impl HashPrefixRow {
    /// Creates a row from its prefix and native-endian height.
    pub const fn new(prefix: HashPrefix, height: u32) -> Self {
        Self {
            prefix,
            height: encode_height(height),
        }
    }

    /// Returns the native-endian block height.
    pub const fn height(self) -> u32 {
        decode_height(self.height)
    }

    /// Returns the serialized database row.
    pub fn to_db_row(self) -> [u8; HASH_PREFIX_ROW_SIZE] {
        let mut row = [0_u8; HASH_PREFIX_ROW_SIZE];
        row.copy_from_slice(self.as_bytes());
        row
    }
}

/// Protocol-neutral SHA256 identifier for a scriptPubKey.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
)]
#[repr(C)]
pub struct ScriptHash {
    bytes: [u8; 32],
}

impl ScriptHash {
    /// Hashes a Bitcoin script into its script-index identifier.
    pub fn new(script: &[u8]) -> Self {
        Self::from_script_bytes(script)
    }

    /// Hashes raw script bytes into their script-index identifier.
    pub fn from_script_bytes(script: &[u8]) -> Self {
        Self {
            bytes: Sha256::digest(script).into(),
        }
    }

    /// Creates a scripthash from raw SHA256 bytes.
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns the raw SHA256 bytes.
    pub const fn to_byte_array(self) -> [u8; 32] {
        self.bytes
    }

    /// Returns the compact index scan prefix.
    pub const fn prefix(self) -> HashPrefix {
        let bytes = self.bytes;
        [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]
    }
}

/// Row builder for confirmed and unconfirmed script-funding rows.
pub struct ScriptHashRow;

impl ScriptHashRow {
    /// Returns the prefix used to scan rows for a scripthash.
    pub const fn scan_prefix(scripthash: ScriptHash) -> HashPrefix {
        scripthash.prefix()
    }

    /// Builds a database row for a funding occurrence at `height`.
    pub const fn row(scripthash: ScriptHash, height: u32) -> HashPrefixRow {
        HashPrefixRow::new(scripthash.prefix(), height)
    }
}

/// Row builder for spending rows keyed by previous outpoint.
pub struct SpendingPrefixRow;

impl SpendingPrefixRow {
    /// Returns the prefix used to scan rows for a previous outpoint.
    pub fn scan_prefix(outpoint: &OutPoint) -> HashPrefix {
        spending_prefix(outpoint.txid.as_bytes(), outpoint.vout)
    }

    /// Builds a database row for a spending occurrence at `height`.
    pub fn row(outpoint: &OutPoint, height: u32) -> HashPrefixRow {
        HashPrefixRow::new(Self::scan_prefix(outpoint), height)
    }

    /// Builds a database row from zero-copy previous-outpoint parts.
    pub(crate) fn row_parts(
        txid_bytes: &[u8],
        vout: u32,
        height: [u8; HEIGHT_SIZE],
    ) -> HashPrefixRow {
        HashPrefixRow {
            prefix: spending_prefix(txid_bytes, vout),
            height,
        }
    }
}

/// Row builder for transaction-id rows.
pub struct TxidRow;

impl TxidRow {
    /// Returns the prefix used to scan rows for a transaction id.
    pub fn scan_prefix(txid: &Txid) -> HashPrefix {
        txid_prefix(txid.as_bytes())
    }

    /// Builds a database row for a transaction occurrence at `height`.
    pub fn row(txid: &Txid, height: u32) -> HashPrefixRow {
        HashPrefixRow::new(Self::scan_prefix(txid), height)
    }

    /// Builds a database row from zero-copy transaction-id bytes.
    pub(crate) fn row_bytes(txid_bytes: &[u8], height: [u8; HEIGHT_SIZE]) -> HashPrefixRow {
        HashPrefixRow {
            prefix: txid_prefix(txid_bytes),
            height,
        }
    }
}

/// A stable electrs header row containing the raw 80-byte block header.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
)]
#[repr(C)]
pub struct HeaderRow {
    /// Raw Bitcoin block-header bytes in consensus order.
    pub header: [u8; HEADER_ROW_SIZE],
}

impl HeaderRow {
    /// Creates a header row from raw consensus header bytes.
    pub const fn new(header: [u8; HEADER_ROW_SIZE]) -> Self {
        Self { header }
    }

    /// Copies a header row from a byte slice.
    pub fn from_header_bytes(bytes: &[u8]) -> Option<Self> {
        let header = bytes.try_into().ok()?;
        Some(Self { header })
    }

    /// Returns the serialized 80-byte header.
    pub const fn to_db_row(self) -> [u8; HEADER_ROW_SIZE] {
        self.header
    }

    /// Double-SHA256 of the header, used as the durable `BlockHeaders` key.
    ///
    /// The 80-byte header is identity-bearing, but storing it as the key pays
    /// 80 bytes of LSM key overhead per block. The hash is the same identity
    /// in 32 bytes, and rollback already has the header in hand to re-hash.
    #[must_use]
    pub fn identity_key(self) -> [u8; HEADER_KEY_SIZE] {
        header_identity_key(&self.header)
    }
}

/// Durable `BlockHeaders` key for a serialized header.
#[must_use]
pub fn header_identity_key(header: &[u8; HEADER_ROW_SIZE]) -> [u8; HEADER_KEY_SIZE] {
    encode::double_sha256(header).to_le_bytes()
}

/// Byte width of one live script-index row key: `scan-prefix || txid || vout_u24`.
pub const SCRIPT_LIVE_ROW_SIZE: usize = HASH_PREFIX_LEN + 32 + 3;

/// One live-output row: a currently unspent outpoint filed under its script.
///
/// The key is the whole row -- `scan-prefix(8) || txid(32, little-endian as
/// rust-bitcoin serializes it) || vout(3, little-endian u24)` -- and the value is
/// empty. The 8-byte prefix is lossy exactly like `Funding`'s (readers
/// exact-check the resolved coin's `script_pubkey`), but the outpoint half is
/// complete: `txid || vout` is injective, so two scripts that collide on the
/// prefix can never collide on a whole key. That is what makes a **point
/// delete collision-safe**: removing a spent output deletes one exact key and
/// cannot touch a colliding script's rows. Prefix-range scans over this family
/// are read-only by contract; a delete is always a whole-key point delete.
///
/// `vout` is packed to 3 bytes. Consensus transaction output counts cannot
/// reach `2^24` under the serialized-block size cap, so this does not drop
/// identity bits.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(C)]
pub struct ScriptLiveRow {
    key: [u8; SCRIPT_LIVE_ROW_SIZE],
}

impl ScriptLiveRow {
    /// Builds the row for `outpoint` held by a script hashing to `scripthash`.
    pub fn new(scripthash: ScriptHash, outpoint: &OutPoint) -> Self {
        debug_assert!(outpoint.vout <= U24_MAX);
        let mut key = [0_u8; SCRIPT_LIVE_ROW_SIZE];
        key[..HASH_PREFIX_LEN].copy_from_slice(&ScriptHashRow::scan_prefix(scripthash));
        key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + 32].copy_from_slice(outpoint.txid.as_bytes());
        key[HASH_PREFIX_LEN + 32..].copy_from_slice(&encode_u24_le(outpoint.vout));
        Self { key }
    }

    /// Rebuilds a row from stored key bytes, refusing any other length.
    pub fn from_db_row(bytes: &[u8]) -> Option<Self> {
        let key: [u8; SCRIPT_LIVE_ROW_SIZE] = bytes.try_into().ok()?;
        Some(Self { key })
    }

    /// The exact stored key.
    pub const fn as_bytes(&self) -> &[u8; SCRIPT_LIVE_ROW_SIZE] {
        &self.key
    }

    /// The outpoint this row locates, for resolution against authoritative
    /// UTXO state.
    pub fn outpoint(&self) -> OutPoint {
        let mut txid = [0_u8; 32];
        txid.copy_from_slice(&self.key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + 32]);
        let mut vout = [0_u8; 3];
        vout.copy_from_slice(&self.key[HASH_PREFIX_LEN + 32..]);
        OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), decode_u24_le(vout))
    }
}

/// Serialized byte length of one [`TxPosition`].
pub const TX_POSITION_SIZE: usize = 6;

/// Byte position of one transaction within its block's serialized body.
///
/// Both fields are 24-bit little-endian integers. Consensus-serialized blocks
/// cannot exceed 4 MiB, which fits in 22 bits, so two bytes of the previous
/// `u32` pair were unused on every row. Alignment stays 1 so the type can be
/// read in place from an arbitrary row-value slice.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Hash,
    Serialize,
    Deserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
)]
#[repr(C)]
pub struct TxPosition {
    /// Byte offset of the transaction from the start of the serialized block.
    offset: [u8; 3],
    /// Consensus-serialized byte length of the transaction.
    len: [u8; 3],
}

/// Ordered numerically, so sorting a position list puts it in block order.
///
/// Deriving `Ord` would compare the little-endian byte arrays lexicographically,
/// least-significant byte first — offset 256 would sort before offset 1. The
/// stored order is what a reader emits entries in, and it has to match the order
/// a full block scan produces, so this cannot be left to the derive.
impl Ord for TxPosition {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.offset()
            .cmp(&other.offset())
            .then_with(|| self.byte_len().cmp(&other.byte_len()))
    }
}

impl PartialOrd for TxPosition {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TxPosition {
    /// Creates a position from a native-endian offset and length.
    #[must_use]
    pub const fn new(offset: u32, byte_len: u32) -> Self {
        debug_assert!(offset <= U24_MAX && byte_len <= U24_MAX);
        Self {
            offset: encode_u24_le(offset),
            len: encode_u24_le(byte_len),
        }
    }

    /// Returns the native-endian byte offset within the serialized block.
    #[must_use]
    pub const fn offset(self) -> u32 {
        decode_u24_le(self.offset)
    }

    /// Returns the native-endian serialized transaction length.
    #[must_use]
    pub const fn byte_len(self) -> u32 {
        decode_u24_le(self.len)
    }

    /// Returns the exclusive end offset, or `None` on overflow.
    #[must_use]
    pub const fn end(self) -> Option<u32> {
        self.offset().checked_add(self.byte_len())
    }
}

/// Codec for the row value carrying a row's transaction byte positions.
///
/// Layout: a packed `TxPosition[n]`, `n >= 1`. A row exists only because at
/// least one transaction produced it, so an **empty** value never means "this
/// block has no matching transactions" — it means the row predates this format.
/// Readers must treat empty and malformed values identically: no usable
/// positions, scan the block.
///
/// # Staleness
///
/// The value does not carry block identity. The durable index supplies that
/// identity by committing every row change with an exact full-hash watermark.
/// The single writer rolls rows back before it writes a replacement block, and
/// snapshot queries accept rows only while that watermark equals the applied
/// tip and the revision and tip stay unchanged. In that valid state, positions
/// belong to the canonical block hash used for the read.
///
/// Readers still validate the complete position list before I/O and exact-check
/// every decoded transaction. If one position is malformed, unavailable, or
/// does not match the requested transaction or script, the reader must discard
/// all tentative results for that row and scan the full block. It must never
/// skip one position and keep the rest. A stale row under an accepted watermark
/// means manual mutation, broken backend atomicity, or storage corruption; it is
/// outside the valid index-state contract.
pub struct TxPositionValue;

impl TxPositionValue {
    /// Encodes positions into a row value.
    #[must_use]
    pub fn encode(positions: &[TxPosition]) -> Vec<u8> {
        positions.as_bytes().to_vec()
    }

    /// Decodes a row value into its positions.
    ///
    /// Returns `None` for an empty or malformed value. The resolver treats an
    /// unavailable position list as a signal to use its all-or-scan safety path.
    #[must_use]
    pub fn decode(value: &[u8]) -> Option<&[TxPosition]> {
        if value.is_empty() {
            return None;
        }
        <[TxPosition]>::ref_from_bytes(value).ok()
    }
}

fn txid_prefix(txid_bytes: &[u8]) -> HashPrefix {
    let mut prefix = [0_u8; HASH_PREFIX_LEN];
    prefix.copy_from_slice(&txid_bytes[..HASH_PREFIX_LEN]);
    prefix
}

fn spending_prefix(txid_bytes: &[u8], vout: u32) -> HashPrefix {
    // Inherited electrs wrapping: the 8-byte txid prefix is interpreted as a
    // big-endian integer, `vout` is added wrapping, and the sum is stored
    // big-endian. Heights in the same key are big-endian too, so the mixed
    // arithmetic is only in this prefix, not in the height suffix.
    let mut prefix = [0_u8; HASH_PREFIX_LEN];
    prefix.copy_from_slice(&txid_bytes[..HASH_PREFIX_LEN]);
    let value = u64::from_be_bytes(prefix).wrapping_add(u64::from(vout));
    value.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{Hash256, OutPoint, Txid, encode};

    use super::{
        HASH_PREFIX_LEN, HEADER_KEY_SIZE, HashPrefixRow, ScriptHash, ScriptHashRow, ScriptLiveRow,
        SpendingPrefixRow, TX_POSITION_SIZE, TxPosition, TxPositionValue, TxidRow,
        header_identity_key,
    };

    #[test]
    fn hash_prefix_row_uses_sortable_height() {
        let row = HashPrefixRow::new([0xa3, 0x84, 0x49, 0x1d, 0x38, 0x92, 0x9f, 0xcc], 123_456);
        assert_eq!(
            row.to_db_row(),
            [
                0xa3, 0x84, 0x49, 0x1d, 0x38, 0x92, 0x9f, 0xcc, 0x00, 0x01, 0xe2, 0x40
            ]
        );
        assert_eq!(row.height(), 123_456);
        // Height 256 must sort after height 1 within one prefix.
        let first = HashPrefixRow::new([0; 8], 1);
        let later = HashPrefixRow::new([0; 8], 256);
        assert!(first.to_db_row() < later.to_db_row());
    }

    #[test]
    fn spending_prefix_matches_electrs_wrapping_prefix() {
        let bytes = [
            31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        ];
        let txid = Txid::from(Hash256::from_le_bytes(&bytes));
        let outpoint = OutPoint::new(txid, 255);
        assert_eq!(
            SpendingPrefixRow::scan_prefix(&outpoint),
            [31, 30, 29, 28, 27, 26, 26, 23]
        );
    }

    #[test]
    fn row_builders_use_hash_prefixes() {
        let scripthash = ScriptHash::from_byte_array([7_u8; 32]);
        let txid = Txid::from(Hash256::from_le_bytes(&[9_u8; 32]));
        assert_eq!(ScriptHashRow::row(scripthash, 5).prefix, [7_u8; 8]);
        assert_eq!(TxidRow::row(&txid, 6).prefix, [9_u8; 8]);
    }

    #[test]
    fn script_live_row_roundtrips_outpoint() {
        let scripthash = ScriptHash::from_byte_array([7_u8; 32]);
        // Nonuniform so a reversed-endian writer cannot satisfy the stored-byte
        // assertion; a palindrome such as `[9; 32]` would.
        let txid_le = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let txid = Txid::from(Hash256::from_le_bytes(&txid_le));
        let outpoint = OutPoint::new(txid, 0x000b_0c0d);
        let row = ScriptLiveRow::new(scripthash, &outpoint);

        assert_eq!(&row.as_bytes()[..HASH_PREFIX_LEN], &[7_u8; 8]);
        assert_eq!(
            &row.as_bytes()[HASH_PREFIX_LEN..HASH_PREFIX_LEN + 32],
            &txid_le
        );
        assert_eq!(&row.as_bytes()[HASH_PREFIX_LEN + 32..], &[0x0d, 0x0c, 0x0b]);
        assert_eq!(row.outpoint(), outpoint);
        assert_eq!(
            ScriptLiveRow::from_db_row(row.as_bytes().as_slice()),
            Some(row)
        );
    }

    #[test]
    fn colliding_script_prefixes_keep_distinct_live_keys() {
        let txid = Txid::from(Hash256::from_le_bytes(&[9_u8; 32]));
        let outpoint = OutPoint::new(txid, 1);
        let a = ScriptHash::from_byte_array({
            let mut bytes = [1_u8; 32];
            bytes[8] = 0xaa;
            bytes
        });
        let b = ScriptHash::from_byte_array({
            let mut bytes = [1_u8; 32];
            bytes[8] = 0xbb;
            bytes
        });
        assert_eq!(a.prefix(), b.prefix());
        let row_a = ScriptLiveRow::new(a, &outpoint);
        let row_b = ScriptLiveRow::new(b, &outpoint);
        // Same prefix and same outpoint is the same live key: two scripts that
        // collide on the prefix cannot both own this outpoint, because one
        // output has one script. Distinct outpoints stay distinct keys.
        assert_eq!(row_a.as_bytes(), row_b.as_bytes());
        let other = OutPoint::new(txid, 2);
        assert_ne!(
            ScriptLiveRow::new(a, &outpoint).as_bytes(),
            ScriptLiveRow::new(b, &other).as_bytes()
        );
    }

    #[test]
    fn packed_positions_are_six_bytes_and_round_trip() {
        assert_eq!(TX_POSITION_SIZE, 6);
        let positions = [TxPosition::new(100, 200), TxPosition::new(300, 400)];
        let encoded = TxPositionValue::encode(&positions);
        assert_eq!(encoded.len(), 12);
        assert_eq!(
            TxPositionValue::decode(&encoded),
            Some(positions.as_slice())
        );
        // A delta-coded u24 offset would still be 3 bytes per subsequent
        // offset, so it cannot beat packed 6-byte entries without a varint.
        // n=1 is the common row, where packed and delta are the same width.
        assert_eq!(TxPositionValue::encode(&[TxPosition::new(1, 2)]).len(), 6);
    }

    #[test]
    fn header_identity_key_is_double_sha256() {
        let header = [0xab_u8; 80];
        let key = header_identity_key(&header);
        assert_eq!(key.len(), HEADER_KEY_SIZE);
        assert_eq!(key, encode::double_sha256(&header).to_le_bytes());
        assert_ne!(key, header[..HEADER_KEY_SIZE]);
    }
}
