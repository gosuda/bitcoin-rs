use bitcoin_rs_primitives::{Hash256, encode::double_sha256};

/// Computes the next BIP157 compact-filter header.
///
/// BIP157 commits to `sha256d(sha256d(filter_bytes) || prev_filter_header)`,
/// with hashes serialized in Bitcoin's internal little-endian byte order.
#[must_use]
pub fn next_header(prev_header: Hash256, filter_bytes: &[u8]) -> Hash256 {
    let filter_hash = double_sha256(filter_bytes);
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(filter_hash.as_byte_array());
    preimage[32..].copy_from_slice(prev_header.as_byte_array());
    double_sha256(&preimage)
}

#[cfg(test)]
mod tests {
    use super::next_header;
    use bitcoin_rs_primitives::Hash256;

    #[test]
    fn chains_genesis_vector_header() {
        let prev = Hash256::default();
        let filter = [0x01, 0x9d, 0xfc, 0xa8];
        let expected = Hash256::from_str_be(
            "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750",
        )
        .unwrap_or_else(|error| panic!("valid test hash: {error}"));

        assert_eq!(next_header(prev, &filter), expected);
    }
}
