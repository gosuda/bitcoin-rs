use bitcoin::consensus::Encodable;
use sha2::{Digest, Sha256};

use crate::{Hash256, encode::Sha256Writer};

/// A Bitcoin block header wrapper.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header(pub bitcoin::block::Header);

impl Header {
    /// Computes the block header hash from the 80-byte consensus serialization.
    #[must_use]
    pub fn compute_hash(&self) -> Hash256 {
        let mut engine = Sha256::new();
        let mut writer = Sha256Writer(&mut engine);
        if let Err(error) = self.0.consensus_encode(&mut writer) {
            unreachable!("sha256 writer is infallible: {error}");
        }
        let first = engine.finalize();
        let second = Sha256::digest(first);
        let bytes = second.into();
        Hash256::from_le_bytes(&bytes)
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
