use bitcoin_rs_consensus::primitives::{Block, BlockImage, Header, Tx};

pub mod block_memory;
pub use block_memory::BlockMemory;
pub use block_memory::BlockMemoryCredit;

pub struct InboundBlock {
    payload: BlockImage,
    pub source: Option<crate::PeerSource>,
    pub forward_credit: Option<crate::connection::BlockForwardCredit>,
    pub memory_credit: Option<block_memory::BlockMemoryCredit>,
}
pub struct InboundHeaders {
    pub headers: Vec<Header>,
    pub source: Option<crate::PeerSource>,
    pub wire_response: bool,
}

pub struct InboundTx {
    pub tx: Tx,
    pub source: crate::PeerSource,
    pub memory_credit: Option<block_memory::BlockMemoryCredit>,
}

impl InboundTx {
    #[must_use]
    pub fn new(tx: Tx, source: crate::PeerSource) -> Self {
        Self {
            tx,
            source,
            memory_credit: None,
        }
    }

    #[must_use]
    pub fn with_memory_credit(mut self, credit: Option<block_memory::BlockMemoryCredit>) -> Self {
        self.memory_credit = credit;
        self
    }
}

impl InboundBlock {
    #[must_use]
    pub fn from_local(block: Block) -> Self {
        Self {
            payload: BlockImage::from_local(block),
            source: None,
            forward_credit: None,
            memory_credit: None,
        }
    }

    pub(crate) fn new(
        payload: BlockImage,
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
    pub fn payload(&self) -> &BlockImage {
        &self.payload
    }

    #[must_use]
    pub fn into_payload(self) -> BlockImage {
        self.payload
    }
}
