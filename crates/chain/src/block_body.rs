//! Neutral block-body read seam.
//!
//! Headers live on [`crate::BlockTree`]. Bodies are stored elsewhere. This
//! trait is the one lookup both P2P inventory serving and index/RPC readers
//! use; it is not an RPC type.

use bitcoin_rs_primitives::BlockHash;

/// Block payload facts available without materializing a full block body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockBodyMetadata {
    /// Serialized block byte length.
    pub body_size: usize,
    /// Number of transactions encoded in the block.
    pub tx_count: usize,
}

/// Storage-backed block body reader used when headers and bodies are stored
/// separately.
pub trait BlockBodySource: Send + Sync {
    /// Returns serialized block bytes for `height` and `hash`, if available.
    fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>>;

    /// Returns indexed body facts. Implementations that cannot answer without
    /// I/O may leave this absent; header-only callers then remain header-only.
    fn block_body_metadata(&self, _height: u32, _hash: BlockHash) -> Option<BlockBodyMetadata> {
        None
    }

    /// Bytes this source's block storage currently occupies on disk.
    ///
    /// `None` means this source does not know. Callers that need a figure
    /// for `getblockchaininfo` then fall back to the sum of recorded sizes.
    fn disk_usage(&self) -> Option<u64> {
        None
    }

    /// Returns `len` body bytes starting `offset` bytes into the serialized
    /// block, letting a caller read one transaction without materializing the
    /// whole body.
    ///
    /// Defaults to `None` so a backend that cannot slice keeps working:
    /// callers must treat `None` as "read the whole body instead", never as
    /// "those bytes do not exist". An out-of-range request also yields
    /// `None` rather than a short read.
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
