//! Inbound payloads received from peers.

/// A block received from a peer with its wire payload preserved.
///
/// `serialized` is the exact P2P message payload and matches the canonical
/// consensus serialization of `block`.
pub struct InboundBlock {
    /// Decoded block.
    pub block: bitcoin::Block,
    /// Wire-format block payload bytes.
    pub serialized: bytes::Bytes,
}

impl InboundBlock {
    /// Wraps a decoded block with freshly computed canonical serialization.
    ///
    /// Used by tests and local injection paths that do not preserve wire payloads.
    #[must_use]
    pub fn from_decoded(block: bitcoin::Block) -> Self {
        let serialized = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
        Self { block, serialized }
    }
}
