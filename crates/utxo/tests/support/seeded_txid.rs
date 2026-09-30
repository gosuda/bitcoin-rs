//! Seeded txid fixture shared by the version-4 snapshot suites.

use bitcoin_rs_primitives::Hash256;

/// Spreads `seed` over all 32 bytes, so distinct seeds give distinct txids.
///
/// `snapshot_v4_golden` pins this exact mapping: its fixture was written with
/// tip hash `txid(4_242)`.
pub(crate) fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}
