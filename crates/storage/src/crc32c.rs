//! CRC32C (Castagnoli) checksum shared by the durable-head row and the
//! chainstate journal's record framing.

/// Computes the CRC32C (Castagnoli) checksum of `bytes`.
#[must_use]
pub(crate) fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::crc32c;

    #[test]
    fn known_vector_matches_the_published_crc32c_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }
}
