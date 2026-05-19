use bitcoin::consensus::Encodable;
use sha2::{Digest, Sha256};

use crate::Hash256;

/// Serializes a consensus-encodable value into a byte vector.
#[must_use]
pub fn consensus_bytes<T: Encodable + ?Sized>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Err(error) = value.consensus_encode(&mut bytes) {
        panic!("consensus encoding into Vec failed: {error}");
    }
    bytes
}

/// Computes Bitcoin's double-SHA256 hash and returns the digest bytes as a little-endian hash.
#[must_use]
pub fn double_sha256(bytes: &[u8]) -> Hash256 {
    let first = Sha256::new().chain_update(bytes).finalize();
    let second = Sha256::new().chain_update(first).finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&second);
    Hash256::from_le_bytes(&out)
}
