//! Index-keyed txid fixture shared by the coinstats suites.

use bitcoin_rs_primitives::Hash256;

/// Writes `index` into the first four bytes, so distinct indexes give
/// distinct txids.
pub(crate) fn txid(index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}
