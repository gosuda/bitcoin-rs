use core::hash::{BuildHasher, BuildHasherDefault};

use bitcoin_rs_primitives::Txid;
use nohash_hasher::NoHashHasher;

pub(crate) type UtxoBuildHasher = BuildHasherDefault<NoHashHasher<u64>>;

/// Eight-byte transaction-id prefix used as the UTXO map key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct UtxoKey([u8; 8]);

impl UtxoKey {
    pub(crate) const SHARD_COUNT: usize = 256;

    /// Builds a key from the first eight little-endian txid bytes.
    #[must_use]
    #[inline]
    pub(crate) fn from_txid(txid: &Txid) -> Self {
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&txid.as_bytes()[..8]);
        Self(prefix)
    }

    #[must_use]
    #[inline]
    pub(crate) const fn from_prefix(prefix: [u8; 8]) -> Self {
        Self(prefix)
    }

    #[must_use]
    #[inline]
    pub(crate) const fn shard(self) -> u8 {
        self.0[0]
    }

    #[must_use]
    #[inline]
    pub(crate) const fn as_u64(self) -> u64 {
        u64::from_le_bytes(self.0)
    }

    #[must_use]
    #[inline]
    pub(crate) const fn to_prefix(self) -> [u8; 8] {
        self.0
    }

    #[must_use]
    #[inline]
    pub(crate) fn hash(self) -> u64 {
        UtxoBuildHasher::default().hash_one(self.as_u64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
