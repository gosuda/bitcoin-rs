use bitcoin::block::{BlockHash, Header};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};

use crate::fsm::step;
use crate::handshake::feature_messages;
use crate::inv::{is_within_inventory_bound, request_inventory};
use crate::peer::{Peer, PeerState};
use crate::wire::{Message, PeerError};

/// Maximum headers returned by one `headers` response.
pub const MAX_HEADERS_RESPONSE: usize = 2_000;
/// Maximum block locator hashes accepted in one `getheaders` request.
pub const MAX_LOCATOR_HASHES: usize = 101;

/// Blocks and missing inventory resolved for one `getdata` request.
#[derive(Debug, Default)]
pub struct InventoryResponse {
    /// Locally available active-chain blocks, sent as `block` messages.
    pub blocks: Vec<bitcoin::Block>,
    /// Inventory that cannot be served by this node.
    pub not_found: Vec<Inventory>,
}

/// Read-only active-chain view used by server-side P2P responders.
pub trait ChainQuery: Send + Sync {
    /// Returns a bounded contiguous active-chain header response.
    fn headers_after(
        &self,
        locator_hashes: &[BlockHash],
        stop_hash: BlockHash,
        limit: usize,
    ) -> Vec<Header>;

    /// Resolves a bounded inventory request into available blocks and misses.
    fn blocks_for_inventory(&self, items: &[Inventory]) -> InventoryResponse;
}

/// Dispatch one inbound message and return protocol responses to send.
pub fn dispatch_inbound<S>(
    peer: &mut Peer<S>,
    message: &Message,
) -> Result<Vec<Message>, PeerError> {
    dispatch_inbound_with_chain(peer, message, None)
}

/// Dispatch one inbound message with an optional active-chain query view.
pub fn dispatch_inbound_with_chain<S>(
    peer: &mut Peer<S>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
) -> Result<Vec<Message>, PeerError> {
    let mut responses = Vec::new();

    match message {
        Message::Version(_) => {
            step(peer, message)?;
            responses.extend(feature_messages());
            responses.push(Message::Verack);
        }
        Message::Ping(nonce) => {
            step(peer, message)?;
            responses.push(Message::Pong(*nonce));
        }
        Message::Inv(items) => {
            step(peer, message)?;
            if let Some(response) = request_inventory(items) {
                responses.push(response);
            }
        }
        Message::GetHeaders(request) => {
            ensure_headers_request_within_bounds(request)?;
            step(peer, message)?;
            responses.push(headers_response(chain, request));
        }
        Message::GetData(items) => {
            ensure_inventory_request_within_bounds(items)?;
            step(peer, message)?;
            responses.extend(data_responses(chain, items));
        }
        _ => step(peer, message)?,
    }

    if peer.state == PeerState::Ready {
        tracing::trace!("peer handshake ready");
    }

    Ok(responses)
}

fn headers_response(chain: Option<&dyn ChainQuery>, request: &GetHeadersMessage) -> Message {
    let mut headers = chain.map_or_else(Vec::new, |chain| {
        chain.headers_after(
            &request.locator_hashes,
            request.stop_hash,
            MAX_HEADERS_RESPONSE,
        )
    });
    headers.truncate(MAX_HEADERS_RESPONSE);
    Message::Headers(headers)
}

fn data_responses(chain: Option<&dyn ChainQuery>, items: &[Inventory]) -> Vec<Message> {
    if items.is_empty() {
        return Vec::new();
    }

    let response = chain.map_or_else(
        || InventoryResponse {
            blocks: Vec::new(),
            not_found: items.to_vec(),
        },
        |chain| chain.blocks_for_inventory(items),
    );

    let mut messages: Vec<_> = response.blocks.into_iter().map(Message::Block).collect();
    if !response.not_found.is_empty() {
        messages.push(Message::NotFound(response.not_found));
    }
    messages
}

fn ensure_headers_request_within_bounds(request: &GetHeadersMessage) -> Result<(), PeerError> {
    if request.locator_hashes.len() > MAX_LOCATOR_HASHES {
        return Err(PeerError::Protocol("getheaders locator too large"));
    }
    Ok(())
}

fn ensure_inventory_request_within_bounds(items: &[Inventory]) -> Result<(), PeerError> {
    if !is_within_inventory_bound(items) {
        return Err(PeerError::Protocol("getdata inventory too large"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
    use bitcoin::pow::CompactTarget;
    use bitcoin::{Block, TxMerkleNode};

    use super::{
        ChainQuery, InventoryResponse, MAX_HEADERS_RESPONSE, MAX_LOCATOR_HASHES, dispatch_inbound,
        dispatch_inbound_with_chain,
    };
    use crate::inv::MAX_INV_PER_MSG;
    use crate::peer::{Peer, PeerState};
    use crate::wire::{Message, PeerError};

    #[derive(Default)]
    struct FakeChain {
        headers: Vec<Header>,
        blocks: Vec<Block>,
        not_found: Vec<Inventory>,
    }

    impl FakeChain {
        fn with_headers(count: u32) -> Self {
            let mut headers = Vec::new();
            let mut prev = bitcoin::BlockHash::all_zeros();
            for nonce in 0..count {
                let header = test_header(prev, nonce);
                prev = header.block_hash();
                headers.push(header);
            }
            Self {
                headers,
                blocks: Vec::new(),
                not_found: Vec::new(),
            }
        }
    }

    impl ChainQuery for FakeChain {
        fn headers_after(
            &self,
            _locator_hashes: &[bitcoin::BlockHash],
            _stop_hash: bitcoin::BlockHash,
            limit: usize,
        ) -> Vec<Header> {
            self.headers.iter().take(limit).copied().collect()
        }

        fn blocks_for_inventory(&self, _items: &[Inventory]) -> InventoryResponse {
            InventoryResponse {
                blocks: self.blocks.clone(),
                not_found: self.not_found.clone(),
            }
        }
    }

    struct GreedyHeaders {
        headers: Vec<Header>,
    }

    impl ChainQuery for GreedyHeaders {
        fn headers_after(
            &self,
            _locator_hashes: &[bitcoin::BlockHash],
            _stop_hash: bitcoin::BlockHash,
            _limit: usize,
        ) -> Vec<Header> {
            self.headers.clone()
        }

        fn blocks_for_inventory(&self, _items: &[Inventory]) -> InventoryResponse {
            InventoryResponse::default()
        }
    }

    #[test]
    fn getheaders_returns_chain_query_headers() -> Result<(), PeerError> {
        let chain = FakeChain::with_headers(2);
        let message = Message::GetHeaders(GetHeadersMessage::new(
            vec![bitcoin::BlockHash::all_zeros()],
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();

        let responses = dispatch_inbound_with_chain(&mut peer, &message, Some(&chain))?;

        let [Message::Headers(headers)] = responses.as_slice() else {
            panic!("expected one headers response, got {responses:?}");
        };
        assert_eq!(headers.len(), 2);
        Ok(())
    }

    #[test]
    fn getheaders_truncates_chain_response_above_protocol_cap() -> Result<(), PeerError> {
        let count = u32::try_from(MAX_HEADERS_RESPONSE + 1)
            .map_err(|_| PeerError::Protocol("test header count overflow"))?;
        let chain = GreedyHeaders {
            headers: FakeChain::with_headers(count).headers,
        };
        let message = Message::GetHeaders(GetHeadersMessage::new(
            vec![bitcoin::BlockHash::all_zeros()],
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();

        let responses = dispatch_inbound_with_chain(&mut peer, &message, Some(&chain))?;

        let [Message::Headers(headers)] = responses.as_slice() else {
            panic!("expected one headers response, got {responses:?}");
        };
        assert_eq!(headers.len(), MAX_HEADERS_RESPONSE);
        Ok(())
    }

    #[test]
    fn oversized_getheaders_locator_is_protocol_error() {
        let locator = vec![bitcoin::BlockHash::all_zeros(); MAX_LOCATOR_HASHES + 1];
        let message = Message::GetHeaders(GetHeadersMessage::new(
            locator,
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();
        let before = peer_snapshot(&peer);

        let result = dispatch_inbound(&mut peer, &message);

        assert!(matches!(
            result,
            Err(PeerError::Protocol("getheaders locator too large"))
        ));
        assert_eq!(peer_snapshot(&peer), before);
    }

    #[test]
    fn getdata_serves_available_blocks_and_reports_missing_inventory() -> Result<(), PeerError> {
        let mut chain = FakeChain::with_headers(1);
        let block = Block {
            header: chain.headers[0],
            txdata: Vec::new(),
        };
        let missing = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([7; 32]));
        chain.blocks.push(block);
        chain.not_found.push(missing);
        let message = Message::GetData(vec![
            Inventory::Block(chain.headers[0].block_hash()),
            missing,
        ]);
        let mut peer = ready_peer();

        let responses = dispatch_inbound_with_chain(&mut peer, &message, Some(&chain))?;

        let [Message::Block(found), Message::NotFound(not_found)] = responses.as_slice() else {
            panic!("expected block plus notfound, got {responses:?}");
        };
        assert_eq!(found.block_hash(), chain.headers[0].block_hash());
        assert_eq!(not_found, &vec![missing]);
        Ok(())
    }

    #[test]
    fn getdata_without_chain_reports_notfound() -> Result<(), PeerError> {
        let hash = bitcoin::BlockHash::all_zeros();
        let message = Message::GetData(vec![Inventory::Block(hash)]);
        let mut peer = ready_peer();

        let responses = dispatch_inbound(&mut peer, &message)?;

        let [Message::NotFound(not_found)] = responses.as_slice() else {
            panic!("expected notfound, got {responses:?}");
        };
        assert_eq!(not_found, &vec![Inventory::Block(hash)]);
        Ok(())
    }

    #[test]
    fn oversized_getdata_inventory_is_protocol_error() {
        let hash = bitcoin::BlockHash::all_zeros();
        let inventory = vec![Inventory::Block(hash); MAX_INV_PER_MSG + 1];
        let message = Message::GetData(inventory);
        let mut peer = ready_peer();
        let before = peer_snapshot(&peer);

        let result = dispatch_inbound(&mut peer, &message);

        assert!(matches!(
            result,
            Err(PeerError::Protocol("getdata inventory too large"))
        ));
        assert_eq!(peer_snapshot(&peer), before);
    }

    #[derive(Debug, PartialEq, Eq)]
    struct PeerSnapshot {
        state: PeerState,
        handshake: (bool, bool),
        capabilities: (bool, bool, bool),
    }

    fn peer_snapshot<S>(peer: &Peer<S>) -> PeerSnapshot {
        PeerSnapshot {
            state: peer.state,
            handshake: (peer.received_verack, peer.remote_version.is_some()),
            capabilities: (
                peer.capabilities.send_headers,
                peer.capabilities.addr_v2,
                peer.wtxid_relay.peer_supported(),
            ),
        }
    }

    fn ready_peer() -> Peer<Cursor<Vec<u8>>> {
        let mut peer = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
        peer.state = PeerState::Ready;
        peer
    }

    fn test_header(prev_blockhash: bitcoin::BlockHash, nonce: u32) -> Header {
        Header {
            version: Version::from_consensus(1),
            prev_blockhash,
            merkle_root: TxMerkleNode::all_zeros(),
            time: nonce,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        }
    }
}
