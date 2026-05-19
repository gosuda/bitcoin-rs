use crate::{Hash256, encode::double_sha256};

/// A Bitcoin block header wrapper.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header(pub bitcoin::block::Header);

impl Header {
    /// Computes the block header hash from the 80-byte consensus serialization.
    #[must_use]
    pub fn compute_hash(&self) -> Hash256 {
        let bytes = crate::encode::consensus_bytes(&self.0);
        double_sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;

    use super::Header;
    use crate::Hash256;

    #[test]
    fn header_hash_matches_bitcoin_crate() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = std::fs::read("tests/testdata/0.bin")?;
        let block: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;
        let header = Header(block.header);
        let expected = Hash256::from_le_bytes(block.header.block_hash().as_byte_array());

        assert_eq!(header.compute_hash(), expected);
        Ok(())
    }
}
