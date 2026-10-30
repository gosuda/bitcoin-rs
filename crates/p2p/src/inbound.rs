//! Inbound payloads received from peers.

use bitcoin_rs_primitives::{Block, BlockPayload, Header, Tx};

pub(crate) mod block_memory;

pub struct InboundBlock {
    payload: BlockPayload,
    pub source: Option<crate::PeerSource>,
    pub(crate) forward_credit: Option<crate::connection::BlockForwardCredit>,
    pub(crate) memory_credit: Option<block_memory::BlockMemoryCredit>,
}
pub struct InboundHeaders {
    pub headers: Vec<Header>,
    pub source: Option<crate::PeerSource>,
    pub wire_response: bool,
}

pub struct InboundTx {
    pub tx: Tx,
    pub source: crate::PeerSource,
}

impl InboundTx {
    #[must_use]
    pub fn new(tx: Tx, source: crate::PeerSource) -> Self {
        Self { tx, source }
    }
}

impl InboundBlock {
    #[must_use]
    pub fn from_local(block: Block) -> Self {
        Self {
            payload: BlockPayload::from_local(block),
            source: None,
            forward_credit: None,
            memory_credit: None,
        }
    }

    pub(crate) fn new(
        payload: BlockPayload,
        source: Option<crate::PeerSource>,
        forward_credit: Option<crate::connection::BlockForwardCredit>,
    ) -> Self {
        Self {
            payload,
            source,
            forward_credit,
            memory_credit: None,
        }
    }

    #[must_use]
    pub fn payload(&self) -> &BlockPayload {
        &self.payload
    }

    #[must_use]
    pub fn into_payload(self) -> BlockPayload {
        self.payload
    }
}
