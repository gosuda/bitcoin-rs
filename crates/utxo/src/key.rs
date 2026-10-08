use core::hash::{BuildHasher, BuildHasherDefault};

use bitcoin_rs_primitives::Txid;
use nohash_hasher::NoHashHasher;

/// Identity build-hasher for the already-uniform 8-byte UTXO key prefix.
pub(crate) type UtxoBuildHasher = BuildHasherDefault<NoHashHasher<u64>>;

/// Eight-byte transaction-id prefix used as the UTXO map key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct UtxoKey([u8; 8]);

impl UtxoKey {
    /// Number of first-byte shards in the in-memory UTXO set.
    pub(crate) const SHARD_COUNT: usize = 256;

    /// Builds a key from the first eight little-endian txid bytes.
    #[must_use]
    #[inline]
    pub(crate) fn from_txid(txid: &Txid) -> Self {
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&txid.as_bytes()[..8]);
        Self(prefix)
    }

    /// Builds a key from a serialized snapshot prefix.
    #[must_use]
    #[inline]
    pub(crate) const fn from_prefix(prefix: [u8; 8]) -> Self {
        Self(prefix)
    }

    /// Returns the shard index selected by the first prefix byte.
    #[must_use]
    #[inline]
    pub(crate) const fn shard(self) -> u8 {
        self.0[0]
    }

    /// Returns the little-endian prefix as a `u64`.
    #[must_use]
    #[inline]
    pub(crate) const fn as_u64(self) -> u64 {
        u64::from_le_bytes(self.0)
    }

    /// Returns the raw eight-byte prefix.
    #[must_use]
    #[inline]
    pub(crate) const fn to_prefix(self) -> [u8; 8] {
        self.0
    }

    /// Returns the identity hash used by `hashbrown::HashTable` operations.
    #[must_use]
    #[inline]
    pub(crate) fn hash(self) -> u64 {
        UtxoBuildHasher::default().hash_one(self.as_u64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shard rule the snapshot/listener test fixtures mirror (first
    /// little-endian txid byte) must track the real key rule: if the shard
    /// scheme ever changes, this fails and the fixtures get updated too.
    #[test]
    fn shard_is_the_first_le_txid_byte() {
        for first in [0_u8, 1, 3, 255] {
            let mut bytes = [0_u8; 32];
            bytes[0] = first;
            bytes[1..9].copy_from_slice(&7_u64.to_le_bytes());
            let key =
                UtxoKey::from_txid(&Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(&bytes)));
            assert_eq!(key.shard(), first);
        }
    }
}
