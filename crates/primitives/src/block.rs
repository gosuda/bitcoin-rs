use bitcoin::hashes::Hash as _;

use crate::{Hash256, Header};

/// A Bitcoin block wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block(pub bitcoin::Block);

impl Block {
    /// Computes the block hash from the block header.
    #[must_use]
    pub fn block_hash(&self) -> Hash256 {
        Header(self.0.header).compute_hash()
    }

    /// Computes all transaction ids in block order.
    #[must_use]
    pub fn txids(&self) -> Vec<Hash256> {
        self.0
            .txdata
            .iter()
            .map(|tx| Hash256::from_le_bytes(tx.compute_txid().as_byte_array()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Block;
    use crate::Hash256;

    #[test]
    fn genesis_block_hash_matches_known_value() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = std::fs::read("tests/testdata/0.bin")?;
        let block = Block(bitcoin::consensus::deserialize(&bytes)?);

        assert_eq!(
            block.block_hash(),
            Hash256::from_str_be(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            )?
        );
        Ok(())
    }
}
