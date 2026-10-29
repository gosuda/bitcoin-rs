use bitcoin_rs_primitives::{BlockBodyMetadata, BlockHash};

#[derive(Debug, Clone, thiserror::Error)]
pub enum BlockBodyReadError {
    #[error("{0}")]
    Corrupt(String),
    #[error("{0}")]
    Read(String),
}

pub trait BlockBodySource: Send + Sync {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, BlockBodyReadError>;

    fn block_body_metadata(&self, _height: u32, _hash: BlockHash) -> Option<BlockBodyMetadata> {
        None
    }

    fn disk_usage(&self) -> Option<u64> {
        None
    }

    fn block_body_range(
        &self,
        _height: u32,
        _hash: BlockHash,
        _offset: u32,
        _len: u32,
    ) -> Option<Vec<u8>> {
        None
    }
}
