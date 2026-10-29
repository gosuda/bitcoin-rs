use bitcoin_rs_primitives::{Hash256, OutPoint, Txid};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub(crate) const HASH_PREFIX_LEN: usize = 8;
/// Number of bytes used for big-endian block heights in index rows.
/// Big-endian makes lexicographic KV order match numeric height order within
pub(crate) const HEIGHT_SIZE: usize = 4;
pub const HASH_PREFIX_ROW_SIZE: usize = HASH_PREFIX_LEN + HEIGHT_SIZE;
pub const HEADER_ROW_SIZE: usize = bitcoin_rs_primitives::Header::LEN;
pub const U24_MAX: u32 = 0x00FF_FFFF;

/// Encodes a block height so lexicographic byte order matches numeric order.
#[must_use]
pub(crate) const fn encode_height(height: u32) -> [u8; HEIGHT_SIZE] {
    height.to_be_bytes()
}

#[must_use]
pub(crate) const fn decode_height(bytes: [u8; HEIGHT_SIZE]) -> u32 {
    u32::from_be_bytes(bytes)
}

const fn encode_u24_le(value: u32) -> [u8; 3] {
    let bytes = value.to_le_bytes();
    [bytes[0], bytes[1], bytes[2]]
}

const fn decode_u24_le(bytes: [u8; 3]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

pub type HashPrefix = [u8; HASH_PREFIX_LEN];

/// A stable electrs hash-prefix row: eight prefix bytes followed by a big-endian height.
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

    pub fn to_db_row(self) -> [u8; HASH_PREFIX_ROW_SIZE] {
        let mut row = [0_u8; HASH_PREFIX_ROW_SIZE];
        row.copy_from_slice(self.as_bytes());
        row
    }
}

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
    pub fn new(script: &[u8]) -> Self {
        Self::from_script_bytes(script)
    }

    pub fn from_script_bytes(script: &[u8]) -> Self {
        Self {
            bytes: Sha256::digest(script).into(),
        }
    }

    pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub const fn to_byte_array(self) -> [u8; 32] {
        self.bytes
    }

    pub const fn prefix(self) -> HashPrefix {
        let bytes = self.bytes;
        [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]
    }
}

pub struct ScriptHashRow;

impl ScriptHashRow {
    pub const fn scan_prefix(scripthash: ScriptHash) -> HashPrefix {
        scripthash.prefix()
    }

    pub const fn row(scripthash: ScriptHash, height: u32) -> HashPrefixRow {
        HashPrefixRow::new(scripthash.prefix(), height)
    }
}

pub struct SpendingPrefixRow;

impl SpendingPrefixRow {
    pub(crate) fn scan_prefix(outpoint: &OutPoint) -> HashPrefix {
        spending_prefix(outpoint.txid.as_bytes(), outpoint.vout)
    }

    pub fn row(outpoint: &OutPoint, height: u32) -> HashPrefixRow {
        HashPrefixRow::new(Self::scan_prefix(outpoint), height)
    }

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

pub(crate) struct TxidRow;

impl TxidRow {
    pub(crate) fn scan_prefix(txid: &Txid) -> HashPrefix {
        txid_prefix(txid.as_bytes())
    }

    #[cfg(test)]
    pub(crate) fn row(txid: &Txid, height: u32) -> HashPrefixRow {
        HashPrefixRow::new(Self::scan_prefix(txid), height)
    }

    pub(crate) fn row_bytes(txid_bytes: &[u8], height: [u8; HEIGHT_SIZE]) -> HashPrefixRow {
        HashPrefixRow {
            prefix: txid_prefix(txid_bytes),
            height,
        }
    }
}

/// Byte width of one live script-index row key: `scan-prefix || txid || vout_u24`.
pub(crate) const SCRIPT_LIVE_ROW_SIZE: usize = HASH_PREFIX_LEN + 32 + 3;

/// The key is the whole row -- `scan-prefix(8) || txid(32, little-endian) ||
/// vout(3, little-endian u24)` -- and the value is empty. This is the full-outpoint
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(C)]
pub struct ScriptLiveRow {
    key: [u8; SCRIPT_LIVE_ROW_SIZE],
}

impl ScriptLiveRow {
    pub fn new(scripthash: ScriptHash, outpoint: &OutPoint) -> Self {
        assert!(outpoint.vout <= U24_MAX, "vout does not fit in u24");
        let mut key = [0_u8; SCRIPT_LIVE_ROW_SIZE];
        key[..HASH_PREFIX_LEN].copy_from_slice(&ScriptHashRow::scan_prefix(scripthash));
        key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + 32].copy_from_slice(outpoint.txid.as_bytes());
        key[HASH_PREFIX_LEN + 32..].copy_from_slice(&encode_u24_le(outpoint.vout));
        Self { key }
    }

    pub(crate) fn from_db_row(bytes: &[u8]) -> Option<Self> {
        let key: [u8; SCRIPT_LIVE_ROW_SIZE] = bytes.try_into().ok()?;
        Some(Self { key })
    }

    pub const fn as_bytes(&self) -> &[u8; SCRIPT_LIVE_ROW_SIZE] {
        &self.key
    }

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

/// Both fields are little-endian byte arrays rather than `u32` so the type has
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
    offset: [u8; 3],
    len: [u8; 3],
}

/// Deriving `Ord` would compare the little-endian byte arrays lexicographically,
/// least-significant byte first — offset 256 would sort before offset 1. The
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
        assert!(
            offset <= U24_MAX && byte_len <= U24_MAX,
            "position does not fit in u24"
        );
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

    #[must_use]
    pub const fn end(self) -> Option<u32> {
        self.offset().checked_add(self.byte_len())
    }
}

/// the query engine and the portable bundle framing apply [`positions_are_valid`],
/// so a row the writer admits is never corrupt to an exporter.
pub(crate) const MAX_POSITION_END_BYTES: usize = 4_000_000;

/// query engine and bundle framing apply before trusting a stored row.
pub(crate) fn positions_are_valid(positions: &[TxPosition]) -> bool {
    let mut previous: Option<TxPosition> = None;
    for &position in positions {
        let Some(end) = position.end() else {
            return false;
        };
        if position.byte_len() == 0
            || usize::try_from(end).map_or(true, |end| end > MAX_POSITION_END_BYTES)
            || previous.is_some_and(|prior| {
                position.offset() <= prior.offset()
                    || position.offset() < prior.end().unwrap_or(u32::MAX)
            })
        {
            return false;
        }
        previous = Some(position);
    }
    true
}

/// Layout: a packed `TxPosition[n]`, `n >= 1`. Writers emit a row only for
/// a nonempty group of positioned transactions. An empty value is corrupt
pub struct TxPositionValue;

impl TxPositionValue {
    #[must_use]
    pub fn encode(positions: &[TxPosition]) -> Vec<u8> {
        positions.as_bytes().to_vec()
    }

    /// rows before using the all-or-scan safety path for other invalid positions.
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
    let mut prefix = [0_u8; HASH_PREFIX_LEN];
    prefix.copy_from_slice(&txid_bytes[..HASH_PREFIX_LEN]);
    let value = u64::from_be_bytes(prefix).wrapping_add(u64::from(vout));
    value.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{Hash256, OutPoint, Txid};

    use super::{HASH_PREFIX_LEN, HashPrefixRow, ScriptHash, ScriptLiveRow, SpendingPrefixRow};

    #[test]
    fn hash_prefix_row_uses_big_endian_height() {
        let row = HashPrefixRow::new([0xa3, 0x84, 0x49, 0x1d, 0x38, 0x92, 0x9f, 0xcc], 123_456);
        assert_eq!(
            row.to_db_row(),
            [
                0xa3, 0x84, 0x49, 0x1d, 0x38, 0x92, 0x9f, 0xcc, 0x00, 0x01, 0xe2, 0x40
            ]
        );
        assert_eq!(row.height(), 123_456);
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
    fn script_live_row_roundtrips_outpoint() {
        let scripthash = ScriptHash::from_byte_array([7_u8; 32]);
        let txid_le = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let txid = Txid::from(Hash256::from_le_bytes(&txid_le));
        let outpoint = OutPoint::new(txid, 0x000a_0b0c);
        let row = ScriptLiveRow::new(scripthash, &outpoint);

        assert_eq!(&row.as_bytes()[..HASH_PREFIX_LEN], &[7_u8; 8]);
        assert_eq!(
            &row.as_bytes()[HASH_PREFIX_LEN..HASH_PREFIX_LEN + 32],
            &txid_le
        );
        assert_eq!(&row.as_bytes()[HASH_PREFIX_LEN + 32..], &[0x0c, 0x0b, 0x0a]);
        assert_eq!(row.outpoint(), outpoint);
        assert_eq!(
            ScriptLiveRow::from_db_row(row.as_bytes().as_slice()),
            Some(row)
        );
    }
}
