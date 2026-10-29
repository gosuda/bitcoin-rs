//! Inbound payloads received from peers.

use bitcoin_rs_primitives::{Block, BlockPayload, Header, Tx};

/// A block received from a peer with its wire payload preserved.
///
/// `payload` owns the decoded block plus the exact P2P message bytes, which
/// match the canonical consensus serialization of the block it carries.
pub struct InboundBlock {
    payload: BlockPayload,
    /// Delivering connection, or `None` for local injection.
    pub source: Option<crate::PeerSource>,
    /// Releases the delivering connection's unsolicited forwarding slot when
    /// this body leaves the ingress path — drained by sync, discarded by the
    /// stager, or rejected. `None` for a locally injected body and for one
    /// the download window already owned.
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
}

/// A transaction received from a peer, ready for mempool admission.
///
/// The node's tx-ingress consumer drains these from the bounded P2P channel
/// and evaluates each through the mempool acceptance policy. `source`
/// identifies the delivering peer so admission origin and relay accounting
/// can attribute the transaction correctly.
pub struct InboundTx {
    pub tx: Tx,
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
    /// Wraps a locally assembled block with its freshly computed canonical
    /// serialization.
    ///
    /// Used by tests and local injection paths that do not preserve wire payloads.
    #[must_use]
    pub fn from_local(block: Block) -> Self {
        Self {
            payload: BlockPayload::from_local(block),
            source: None,
            forward_credit: None,
        }
    }

    /// Assembles a channeled body from its payload and outer delivery state.
    ///
    /// Crate-visible so the ingress handoff can attach `source` and
    /// `forward_credit` without exposing the payload field itself.
    pub(crate) fn new(
        payload: BlockPayload,
        source: Option<crate::PeerSource>,
        forward_credit: Option<crate::connection::BlockForwardCredit>,
    ) -> Self {
        Self {
            payload,
            source,
            forward_credit,
        }
    }

    /// Borrows the owned payload.
    #[must_use]
    pub fn payload(&self) -> &BlockPayload {
        &self.payload
    }

    /// Consumes the block body, returning the owned payload.
    #[must_use]
    pub fn into_payload(self) -> BlockPayload {
        self.payload
    }
}
