use core::hash::{BuildHasher, BuildHasherDefault};

use bitcoin_rs_primitives::Hash256;
use nohash_hasher::NoHashHasher;

/// Identity build-hasher for the already-uniform 8-byte UTXO key prefix.
pub type UtxoBuildHasher = BuildHasherDefault<NoHashHasher<u64>>;

/// Eight-byte transaction-id prefix used as the UTXO map key.
///
/// The prefix is already uniformly distributed by SHA-256d, so shard tables use
/// `NoHashHasher<u64>` through [`UtxoBuildHasher`] rather than spending cycles on
/// an additional hash.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UtxoKey([u8; 8]);

impl UtxoKey {
    /// Number of first-byte shards in the in-memory UTXO set.
    pub const SHARD_COUNT: usize = 256;

    /// Builds a key from the first eight little-endian txid bytes.
    #[must_use]
    pub fn from_txid(txid: &Hash256) -> Self {
        Self(txid.prefix8())
    }

    /// Builds a key from a serialized snapshot prefix.
    #[must_use]
    pub const fn from_prefix(prefix: [u8; 8]) -> Self {
        Self(prefix)
    }

    /// Returns the shard index selected by the first prefix byte.
    #[must_use]
    pub const fn shard(&self) -> u8 {
        self.0[0]
    }

    /// Returns the little-endian prefix as a `u64`.
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }

    /// Returns the raw eight-byte prefix.
    #[must_use]
    pub const fn to_prefix(self) -> [u8; 8] {
        self.0
    }

    /// Returns the identity hash used by `hashbrown::HashTable` operations.
    #[must_use]
    pub fn hash(self) -> u64 {
        UtxoBuildHasher::default().hash_one(self.as_u64())
    }
}
