//! Shard-targeted txid fixture shared by the UTXO commit and coin-stats suites.

use bitcoin_rs_primitives::Hash256;

/// A txid whose first little-endian byte, the byte that selects the UTXO
/// shard, is `shard`; `suffix` varies the remaining bytes within that shard.
pub(crate) fn txid_in_shard(shard: u8, suffix: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[0] = shard;
    bytes[1..9].copy_from_slice(&suffix.to_le_bytes());
    bytes[9..17].copy_from_slice(&suffix.rotate_left(13).to_le_bytes());
    bytes[17..25].copy_from_slice(&suffix.wrapping_mul(29).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}
