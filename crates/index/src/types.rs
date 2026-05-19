use bitcoin::hashes::{Hash as _, sha256};
use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Number of bytes retained from hashes in electrs index rows.
pub const HASH_PREFIX_LEN: usize = 8;
/// Number of bytes used for little-endian block heights in index rows.
pub const HEIGHT_SIZE: usize = 4;
/// Serialized byte length of a hash-prefix row.
pub const HASH_PREFIX_ROW_SIZE: usize = HASH_PREFIX_LEN + HEIGHT_SIZE;
/// Serialized byte length of a Bitcoin block header.
pub const HEADER_ROW_SIZE: usize = 80;

/// Prefix used as the seek key for electrs-style hash-prefix rows.
pub type HashPrefix = [u8; HASH_PREFIX_LEN];

/// A stable electrs hash-prefix row: eight prefix bytes followed by a little-endian height.
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
    /// The transaction-confirming block height, encoded little-endian.
    pub height: [u8; HEIGHT_SIZE],
}

impl HashPrefixRow {
    /// Creates a row from its prefix and native-endian height.
    pub const fn new(prefix: HashPrefix, height: u32) -> Self {
        Self {
            prefix,
            height: height.to_le_bytes(),
        }
    }

    /// Returns the native-endian block height.
    pub const fn height(self) -> u32 {
        u32::from_le_bytes(self.height)
    }

    /// Returns the serialized database row.
    pub fn to_db_row(self) -> [u8; HASH_PREFIX_ROW_SIZE] {
        let mut row = [0_u8; HASH_PREFIX_ROW_SIZE];
        row.copy_from_slice(self.as_bytes());
        row
    }
}

/// Electrum protocol scripthash, defined as SHA256(scriptPubKey bytes).
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
    /// Hashes a Bitcoin script into its Electrum scripthash.
    pub fn new(script: &bitcoin::Script) -> Self {
        Self::from_script_bytes(script.as_bytes())
    }

    /// Hashes raw script bytes into their Electrum scripthash.
    pub fn from_script_bytes(script: &[u8]) -> Self {
        Self {
            bytes: sha256::Hash::hash(script).to_byte_array(),
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

    /// Returns the electrs scan prefix.
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
    pub fn scan_prefix(outpoint: &bitcoin::OutPoint) -> HashPrefix {
        spending_prefix(outpoint.txid.as_ref(), outpoint.vout)
    }

    /// Builds a database row for a spending occurrence at `height`.
    pub fn row(outpoint: &bitcoin::OutPoint, height: u32) -> HashPrefixRow {
        HashPrefixRow::new(Self::scan_prefix(outpoint), height)
    }

    /// Builds a database row from zero-copy previous-outpoint parts.
    pub(crate) fn row_parts(txid_bytes: &[u8], vout: u32, height: u32) -> HashPrefixRow {
        HashPrefixRow::new(spending_prefix(txid_bytes, vout), height)
    }
}

/// Row builder for transaction-id rows.
pub struct TxidRow;

impl TxidRow {
    /// Returns the prefix used to scan rows for a transaction id.
    pub fn scan_prefix(txid: &bitcoin::Txid) -> HashPrefix {
        txid_prefix(txid.as_ref())
    }

    /// Builds a database row for a transaction occurrence at `height`.
    pub fn row(txid: &bitcoin::Txid, height: u32) -> HashPrefixRow {
        HashPrefixRow::new(Self::scan_prefix(txid), height)
    }

    /// Builds a database row from zero-copy transaction-id bytes.
    pub(crate) fn row_bytes(txid_bytes: &[u8], height: u32) -> HashPrefixRow {
        HashPrefixRow::new(txid_prefix(txid_bytes), height)
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

    /// Returns the serialized database row.
    pub const fn to_db_row(self) -> [u8; HEADER_ROW_SIZE] {
        self.header
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
    use super::{HashPrefixRow, ScriptHash, ScriptHashRow, SpendingPrefixRow, TxidRow};
    use bitcoin::hashes::Hash as _;

    #[test]
    fn hash_prefix_row_uses_electrs_layout() {
        let row = HashPrefixRow::new([0xa3, 0x84, 0x49, 0x1d, 0x38, 0x92, 0x9f, 0xcc], 123_456);
        assert_eq!(
            row.to_db_row(),
            [
                0xa3, 0x84, 0x49, 0x1d, 0x38, 0x92, 0x9f, 0xcc, 0x40, 0xe2, 0x01, 0x00
            ]
        );
        assert_eq!(row.height(), 123_456);
    }

    #[test]
    fn spending_prefix_matches_electrs_wrapping_prefix() {
        let txid = bitcoin::Txid::from_byte_array([
            31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
            9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        ]);
        let outpoint = bitcoin::OutPoint { txid, vout: 255 };
        assert_eq!(
            SpendingPrefixRow::scan_prefix(&outpoint),
            [31, 30, 29, 28, 27, 26, 26, 23]
        );
    }

    #[test]
    fn row_builders_use_hash_prefixes() {
        let scripthash = ScriptHash::from_byte_array([7_u8; 32]);
        let txid = bitcoin::Txid::from_byte_array([9_u8; 32]);
        assert_eq!(ScriptHashRow::row(scripthash, 5).prefix, [7_u8; 8]);
        assert_eq!(TxidRow::row(&txid, 6).prefix, [9_u8; 8]);
    }
}
