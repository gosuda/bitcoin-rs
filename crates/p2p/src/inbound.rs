//! Inbound payloads received from peers.

use bitcoin_rs_primitives::{Block, Header, Tx, consensus_bytes};

/// A block received from a peer with its wire payload preserved.
///
/// `serialized` is the exact P2P message payload and matches the canonical
/// consensus serialization of `block`.
pub struct InboundBlock {
    /// Decoded block.
    pub block: Block,
    /// Wire-format block payload bytes.
    pub serialized: bytes::Bytes,
    /// Delivering connection, or `None` for local injection.
    pub source: Option<crate::PeerSource>,
    /// Releases the delivering connection's unsolicited forwarding slot when
    /// this body leaves the ingress path — drained by sync, discarded by the
    /// stager, or rejected. `None` for a locally injected body; a body the
    /// download window already owned carries `Some` wrapping a no-op inner
    /// credit (`BlockForwardCredit(None)`).
    pub(crate) forward_credit: Option<crate::connection::BlockForwardCredit>,
}
/// A `headers` message batch and the peer that delivered it.
pub struct InboundHeaders {
    /// Decoded headers, in wire order.
    pub headers: Vec<Header>,
    /// Delivering connection, or `None` for local injection.
    pub source: Option<crate::PeerSource>,
    /// `true` only for a wire `headers` message; headers forwarded out of a
    /// delivered block body (`false`) reach the same admission path but are
    /// not a response to an outstanding `getheaders` and must not consume
    /// its pending-request state.
    pub wire_response: bool,
    /// `true` when the source already has this batch's tip body fetch in
    /// flight outside the download window — a compact `getblocktxn` or a
    /// fallback `getdata` issued during compact handling. The window records
    /// the hash as pending so it does not schedule a duplicate request;
    /// delivery, expiry, or disconnect resolves it exactly like a window
    /// request.
    pub body_fetch_owned: bool,
}

/// A transaction received from a peer, ready for mempool admission.
///
/// The node's tx-ingress consumer drains these from the bounded P2P channel
/// and evaluates each through the mempool acceptance policy. `source`
/// identifies the delivering peer so admission origin and relay accounting
/// can attribute the transaction correctly.
pub struct InboundTx {
    /// Decoded transaction.
    pub tx: Tx,
    /// Delivering connection.
    pub source: crate::PeerSource,
}

impl InboundTx {
    /// Wraps a decoded transaction with its delivering peer source.
    #[must_use]
    pub fn new(tx: Tx, source: crate::PeerSource) -> Self {
        Self { tx, source }
    }
}

impl InboundBlock {
    /// Wraps a decoded block with freshly computed canonical serialization.
    ///
    /// Used by tests and local injection paths that do not preserve wire payloads.
    #[must_use]
    pub fn from_decoded(block: Block) -> Self {
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        Self {
            block,
            serialized,
            source: None,
            forward_credit: None,
        }
    }
}
