//! Native block header type and header hash computation.

use crate::{
    BlockHash, Hash256,
    encode::{DecodeError, deserialize, double_sha256},
};

/// A Bitcoin block header in native owned form.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// Block version.
    pub version: i32,
    /// Hash of the previous block.
    pub prev_blockhash: BlockHash,
    /// Merkle root of the block's transaction ids.
    pub merkle_root: Hash256,
    /// Unix epoch seconds.
    pub time: u32,
    /// Compact proof-of-work target.
    pub bits: u32,
    /// Proof-of-work nonce.
    pub nonce: u32,
}

impl Header {
    /// Consensus serialization length of a block header.
    pub const LEN: usize = 80;

    /// Writes the 80-byte consensus serialization.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut out = [0_u8; Self::LEN];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(self.prev_blockhash.as_bytes());
        out[36..68].copy_from_slice(self.merkle_root.as_byte_array());
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Reads an 80-byte consensus serialization.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Self {
        let mut version = [0_u8; 4];
        let mut time = [0_u8; 4];
        let mut bits = [0_u8; 4];
        let mut nonce = [0_u8; 4];
        version.copy_from_slice(&bytes[0..4]);
        time.copy_from_slice(&bytes[68..72]);
        bits.copy_from_slice(&bytes[72..76]);
        nonce.copy_from_slice(&bytes[76..80]);
        let mut prev = [0_u8; 32];
        let mut merkle = [0_u8; 32];
        prev.copy_from_slice(&bytes[4..36]);
        merkle.copy_from_slice(&bytes[36..68]);
        Self {
            version: i32::from_le_bytes(version),
            prev_blockhash: BlockHash(Hash256::from_le_bytes(&prev)),
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: u32::from_le_bytes(time),
            bits: u32::from_le_bytes(bits),
            nonce: u32::from_le_bytes(nonce),
        }
    }

    /// Computes the block hash: double-SHA256 of the 80-byte consensus serialization.
    #[must_use]
    pub fn compute_hash(&self) -> BlockHash {
        BlockHash(double_sha256(&self.to_bytes()))
    }

    /// Decodes exactly one 80-byte header, rejecting any trailing bytes.
    pub fn consensus_decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Header;
    use crate::{BlockHash, encode::DecodeError};

    type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

    #[test]
    fn genesis_header_hash_matches_published_id() -> Result<()> {
        let bytes = std::fs::read("tests/testdata/0.bin")?;
        let header = Header::consensus_decode(&bytes[..80])?;

        assert_eq!(header.version, 1);
        assert_eq!(header.time, 1_231_006_505);
        assert_eq!(header.nonce, 2_083_236_893);
        assert_eq!(header.bits, 0x1d00_ffff);
        assert_eq!(
            header.compute_hash(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                .parse::<BlockHash>()?
        );
        assert_eq!(crate::encode::consensus_bytes(&header), &bytes[..80]);
        assert_eq!(header.to_bytes().as_slice(), &bytes[..80]);
        Ok(())
    }

    #[test]
    fn header_decode_rejects_trailing_bytes() -> Result<()> {
        let bytes = std::fs::read("tests/testdata/0.bin")?;
        assert!(Header::consensus_decode(&bytes[..80]).is_ok());

        let mut trailing = bytes[..80].to_vec();
        trailing.push(0xFF);
        assert_eq!(
            Header::consensus_decode(&trailing),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );
        Ok(())
    }
}
