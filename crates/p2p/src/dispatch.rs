use std::cell::RefCell;

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header, Tx, Txid, Wtxid};

use crate::fsm::step;
use crate::handshake::feature_messages;
use crate::inv::{
    inventory_tx_hash, is_within_inventory_bound, request_inventory, request_inventory_filtered,
};
use crate::peer::{Peer, PeerState};
use crate::wire::{Message, PeerError};

/// Maximum headers returned by one `headers` response.
pub const MAX_HEADERS_RESPONSE: usize = 2_000;
/// Maximum block locator hashes accepted in one locator-based request.
pub use crate::wire::MAX_LOCATOR_HASHES;

/// Outcome of streamed inventory serving. Bodies pass through the serving
/// sink as they load and are never materialized as a whole.
#[derive(Debug, Default)]
pub struct InventoryServing {
    /// Inventory this node cannot serve (unknown type, stale, pruned, no
    /// body).
    pub not_found: Vec<Inventory>,
    /// True when production stopped at the headroom gate with items
    /// unexamined. The caller applies the saturation policy; remaining
    /// items are never served (I9: no silent half-serve).
    pub halted: bool,
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

    /// Serves block inventory one body at a time, in `items` order. For each
    /// block-typed item `headroom` is consulted EXACTLY ONCE, immediately
    /// BEFORE its body load; `false` halts production and sets `halted`
    /// (I7, I9). Each loaded body is delivered through `serve`; a `serve`
    /// error aborts production and propagates. Non-block / unservable items
    /// are collected into `not_found` and never loaded.
    fn serve_inventory_blocks(
        &self,
        items: &[Inventory],
        headroom: &dyn Fn() -> bool,
        serve: &mut dyn FnMut(Block) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError>;
}

/// Read-only transaction inventory view used by the Inv filter and the
/// `getdata` tx responder.
///
/// Implemented by the node's admission layer ([`TxAdmission`] in the node
/// crate); the p2p crate never owns mempool, orphan, or rejection state.
/// The dispatch path consults this trait to suppress redundant `getdata`
/// requests for transactions the node already holds and to serve
/// transaction bodies in reply to `getdata`.
pub trait TxInventory: Send + Sync {
    /// Returns `true` when the node already holds the transaction identified
    /// by `hash` — in the mempool, the orphan map, or the recent-rejects
    /// cache. `wtxid_relay` is `true` when the peer negotiated BIP339, in
    /// which case `hash` is a wtxid; otherwise it is a txid.
    fn have_tx(&self, hash: Hash256, wtxid_relay: bool) -> bool;

    /// Returns the witness transaction body for `txid`, or `None` when the
    /// node does not have it. Used to answer `getdata` for txid-typed items.
    fn get_tx(&self, txid: Txid) -> Option<Tx>;

    /// Returns the witness transaction body for `wtxid`, or `None` when the
    /// node does not have it. Used to answer BIP339 `getdata` (`WTx`) items.
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx>;
}

/// Chainless dispatch: collects the protocol responses and returns them.
///
/// With `chain: None` responses can never contain a block body, so the batch
/// is protocol-bounded (at most [`MAX_HEADERS_RESPONSE`] headers, or one
/// inventory-bound notfound/getdata echo) and safe to materialize whole.
pub fn dispatch_inbound<S>(
    peer: &mut Peer<S>,
    message: &Message,
) -> Result<Vec<Message>, PeerError> {
    let responses = RefCell::new(Vec::new());
    dispatch_inbound_with_chain(peer, message, None, &|| true, &mut |response| {
        responses.borrow_mut().push(response);
        Ok(())
    })?;
    Ok(responses.into_inner())
}

/// Dispatch with an active-chain view but no transaction-inventory filter.
///
/// Equivalent to [`dispatch_inbound_full`] with `tx_inventory: None`: every
/// announced tx is requested, and tx-typed `getdata` items are reported
/// missing. Kept for call sites (the listener) that have not yet been wired
/// with a [`TxInventory`] handle.
pub fn dispatch_inbound_with_chain<S>(
    peer: &mut Peer<S>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    dispatch_inbound_full(peer, message, chain, None, headroom, send)
}

/// Dispatch with an active-chain view and a transaction-inventory filter.
///
/// Every response is emitted through `send` in the identical order the
/// former batch form produced (I8); `send` errors abort emission and
/// propagate. `headroom` gates block-body materialization (I7) and is
/// evaluated before each load.
///
/// When `tx_inventory` is `Some`, the `inv` arm suppresses `getdata` for
/// transactions the node already holds (mempool, orphan map, or
/// recent-rejects) and the `getdata` arm serves tx bodies for tx-typed
/// items the node has, reporting the rest as `notfound`. BIP339: when the
/// peer advertised wtxid relay, tx inventory hashes are interpreted as
/// wtxids; otherwise as txids.
pub fn dispatch_inbound_full<S>(
    peer: &mut Peer<S>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    match message {
        Message::Version(_) => {
            step(peer, message)?;
            for response in feature_messages() {
                send(response)?;
            }
            send(Message::Verack)?;
        }
        Message::Ping(nonce) => {
            step(peer, message)?;
            send(Message::Pong(*nonce))?;
        }
        Message::Inv(items) => {
            step(peer, message)?;
            let response = match tx_inventory {
                Some(inv) => {
                    let wtxid_relay = peer.wtxid_relay.peer_supported();
                    request_inventory_filtered(items, &|item| {
                        inventory_tx_hash(item).is_some_and(|hash| inv.have_tx(hash, wtxid_relay))
                    })
                }
                None => request_inventory(items),
            };
            if let Some(response) = response {
                send(response)?;
            }
        }
        Message::GetHeaders(request) => {
            ensure_block_locator_within_bounds(
                &request.locator_hashes,
                "getheaders locator too large",
            )?;
            step(peer, message)?;
            send(headers_response(chain, request))?;
        }
        Message::GetBlocks(request) => {
            ensure_block_locator_within_bounds(
                &request.locator_hashes,
                "getblocks locator too large",
            )?;
            step(peer, message)?;
        }
        Message::GetData(items) => {
            ensure_inventory_request_within_bounds(items)?;
            step(peer, message)?;
            serve_getdata(chain, tx_inventory, items, headroom, send)?;
        }
        _ => step(peer, message)?,
    }

    if peer.state == PeerState::Ready {
        tracing::trace!("peer handshake ready");
    }

    Ok(())
}

fn headers_response(chain: Option<&dyn ChainQuery>, request: &GetHeadersMessage) -> Message {
    let locator_hashes: Vec<BlockHash> = request
        .locator_hashes
        .iter()
        .map(|h| BlockHash(Hash256::from_le_bytes(h.as_byte_array())))
        .collect();
    let stop_hash = BlockHash(Hash256::from_le_bytes(request.stop_hash.as_byte_array()));
    let mut headers = chain.map_or_else(Vec::new, |chain| {
        chain.headers_after(&locator_hashes, stop_hash, MAX_HEADERS_RESPONSE)
    });
    headers.truncate(MAX_HEADERS_RESPONSE);
    Message::Headers(headers)
}

/// Serves one `getdata` through the sink.
///
/// When `tx_inventory` is `None` the behaviour is unchanged from the
/// pre-tx-inventory path: with no chain view the whole request is reported
/// missing; otherwise blocks stream through the chain query behind the
/// headroom gate, followed by at most one trailing `notfound` (I8).
///
/// When `tx_inventory` is `Some`, tx-typed items are served from the
/// transaction inventory (the node's mempool): a held tx is emitted as a
/// `tx` message (witness serialization), and a tx the node does not have is
/// collected into the trailing `notfound`. Block-typed items continue to
/// stream through the chain query behind the headroom gate. BIP339 `WTx`
/// items are resolved by wtxid; `Transaction`/`WitnessTransaction` items by
/// txid.
fn serve_getdata(
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
    items: &[Inventory],
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    if items.is_empty() {
        return Ok(());
    }

    // Fast path: no tx inventory — the original block-only behaviour. This
    // keeps every existing call site (listener, chainless dispatch, tests)
    // byte-identical until a TxInventory handle is wired in.
    let Some(inv) = tx_inventory else {
        return serve_getdata_blocks(chain, items, headroom, send);
    };

    // Item-by-item: tx-typed items resolve through the tx inventory; block
    // items stream through the chain query behind the headroom gate. The
    // trailing notfound collects every unservable item in request order.
    let mut not_found: Vec<Inventory> = Vec::new();
    for item in items {
        match item {
            Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                let native = Txid::from(Hash256::from_le_bytes(txid.as_byte_array()));
                if let Some(tx) = inv.get_tx(native) {
                    send(Message::Tx(tx))?;
                } else {
                    not_found.push(*item);
                }
            }
            Inventory::WTx(wtxid) => {
                let native = Wtxid::from(Hash256::from_le_bytes(wtxid.as_byte_array()));
                if let Some(tx) = inv.get_tx_by_wtxid(native) {
                    send(Message::Tx(tx))?;
                } else {
                    not_found.push(*item);
                }
            }
            // Block-typed and unknown items: resolve through the chain
            // query one at a time so headroom is honoured per load and block
            // misses merge into the single trailing notfound. With no chain
            // view every non-tx item is missing.
            block_item => {
                if let Some(chain) = chain {
                    let outcome = chain.serve_inventory_blocks(
                        std::slice::from_ref(block_item),
                        headroom,
                        &mut |block| send(Message::Block(block)),
                    )?;
                    if outcome.halted {
                        return Err(PeerError::Protocol(
                            "getdata serving halted: outbound production gate",
                        ));
                    }
                    not_found.extend(outcome.not_found);
                } else {
                    not_found.push(*block_item);
                }
            }
        }
    }

    if !not_found.is_empty() {
        send(Message::NotFound(not_found))?;
    }
    Ok(())
}

/// Block-only `getdata` serving: the original pre-tx-inventory path.
fn serve_getdata_blocks(
    chain: Option<&dyn ChainQuery>,
    items: &[Inventory],
    headroom: &dyn Fn() -> bool,
    send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
) -> Result<(), PeerError> {
    match chain {
        None => send(Message::NotFound(items.to_vec()))?,
        Some(chain) => {
            let outcome = chain.serve_inventory_blocks(items, headroom, &mut |block| {
                send(Message::Block(block))
            })?;
            if outcome.halted {
                return Err(PeerError::Protocol(
                    "getdata serving halted: outbound production gate",
                ));
            }
            if !outcome.not_found.is_empty() {
                send(Message::NotFound(outcome.not_found))?;
            }
        }
    }
    Ok(())
}

fn ensure_block_locator_within_bounds(
    locator_hashes: &[bitcoin::BlockHash],
    error: &'static str,
) -> Result<(), PeerError> {
    if locator_hashes.len() > MAX_LOCATOR_HASHES {
        return Err(PeerError::Protocol(error));
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
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
    use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header, Tx, Txid, Wtxid};

    use super::{
        ChainQuery, InventoryServing, MAX_HEADERS_RESPONSE, MAX_LOCATOR_HASHES, TxInventory,
        dispatch_inbound, dispatch_inbound_full, dispatch_inbound_with_chain,
    };
    use crate::connection::{OutboundBudget, PeerLease};
    use crate::inv::MAX_INV_PER_MSG;
    use crate::peer::{Peer, PeerState};
    use crate::wire::{Message, PeerError};

    #[derive(Default)]
    struct FakeChain {
        headers: Vec<Header>,
        blocks: Vec<Block>,
    }

    impl FakeChain {
        fn with_headers(count: u32) -> Self {
            let mut headers = Vec::new();
            let mut prev = BlockHash::default();
            for nonce in 0..count {
                let header = test_header(prev, nonce);
                prev = header.compute_hash();
                headers.push(header);
            }
            Self {
                headers,
                blocks: Vec::new(),
            }
        }

        fn with_block(mut self, block: Block) -> Self {
            self.blocks.push(block);
            self
        }
    }

    impl ChainQuery for FakeChain {
        fn headers_after(
            &self,
            _locator_hashes: &[BlockHash],
            _stop_hash: BlockHash,
            limit: usize,
        ) -> Vec<Header> {
            self.headers.iter().take(limit).copied().collect()
        }

        fn serve_inventory_blocks(
            &self,
            items: &[Inventory],
            headroom: &dyn Fn() -> bool,
            serve: &mut dyn FnMut(Block) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            let mut outcome = InventoryServing::default();
            for item in items {
                let Some(found) = self
                    .blocks
                    .iter()
                    .find(|block| inv_hash(item) == Some(wire_hash(block)))
                else {
                    outcome.not_found.push(*item);
                    continue;
                };
                if !headroom() {
                    outcome.halted = true;
                    return Ok(outcome);
                }
                serve(found.clone())?;
            }
            Ok(outcome)
        }
    }

    /// Streaming fake mirroring `NodeP2pChainQuery`: block-typed items that
    /// resolve to a stored body are served behind `headroom`; everything
    /// else lands in `not_found` without a load.
    fn inv_hash(item: &Inventory) -> Option<[u8; 32]> {
        match item {
            Inventory::Block(hash) | Inventory::WitnessBlock(hash) => Some(hash.to_byte_array()),
            _ => None,
        }
    }

    fn wire_hash(block: &Block) -> [u8; 32] {
        *block.block_hash().as_bytes()
    }

    struct GreedyHeaders {
        headers: Vec<Header>,
    }

    impl ChainQuery for GreedyHeaders {
        fn headers_after(
            &self,
            _locator_hashes: &[BlockHash],
            _stop_hash: BlockHash,
            _limit: usize,
        ) -> Vec<Header> {
            self.headers.clone()
        }

        fn serve_inventory_blocks(
            &self,
            _items: &[Inventory],
            _headroom: &dyn Fn() -> bool,
            _serve: &mut dyn FnMut(Block) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            Ok(InventoryServing::default())
        }
    }

    /// Collecting-sink wrapper mirroring the listener's streaming send.
    fn dispatch_collect<S>(
        peer: &mut Peer<S>,
        message: &Message,
        chain: Option<&dyn ChainQuery>,
    ) -> Result<Vec<Message>, PeerError> {
        let collected = RefCell::new(Vec::new());
        dispatch_inbound_with_chain(peer, message, chain, &|| true, &mut |response| {
            collected.borrow_mut().push(response);
            Ok(())
        })?;
        Ok(collected.into_inner())
    }

    #[test]
    fn getheaders_returns_chain_query_headers() -> Result<(), PeerError> {
        let chain = FakeChain::with_headers(2);
        let message = Message::GetHeaders(GetHeadersMessage::new(
            vec![bitcoin::BlockHash::all_zeros()],
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();

        let responses = dispatch_collect(&mut peer, &message, Some(&chain))?;

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

        let responses = dispatch_collect(&mut peer, &message, Some(&chain))?;

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
    fn oversized_getblocks_locator_is_protocol_error() {
        let locator = vec![bitcoin::BlockHash::all_zeros(); MAX_LOCATOR_HASHES + 1];
        let message = Message::GetBlocks(GetBlocksMessage::new(
            locator,
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();
        let before = peer_snapshot(&peer);

        let result = dispatch_inbound(&mut peer, &message);

        assert!(matches!(
            result,
            Err(PeerError::Protocol("getblocks locator too large"))
        ));
        assert_eq!(peer_snapshot(&peer), before);
    }

    #[test]
    fn getblocks_locator_at_cap_is_accepted() -> Result<(), PeerError> {
        let locator = vec![bitcoin::BlockHash::all_zeros(); MAX_LOCATOR_HASHES];
        let message = Message::GetBlocks(GetBlocksMessage::new(
            locator,
            bitcoin::BlockHash::all_zeros(),
        ));
        let mut peer = ready_peer();

        let responses = dispatch_inbound(&mut peer, &message)?;

        assert!(responses.is_empty());
        assert_eq!(peer.state, PeerState::Ready);
        Ok(())
    }

    #[test]
    fn getdata_serves_available_blocks_and_reports_missing_inventory() -> Result<(), PeerError> {
        let chain = FakeChain::with_headers(1);
        let block = Block {
            header: chain.headers[0],
            txs: Vec::new(),
        };
        let missing = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([7; 32]));
        let chain = chain.with_block(block);
        let message = Message::GetData(vec![
            Inventory::Block(bitcoin::BlockHash::from_byte_array(
                *chain.headers[0].compute_hash().as_bytes(),
            )),
            missing,
        ]);
        let mut peer = ready_peer();

        let responses = dispatch_collect(&mut peer, &message, Some(&chain))?;

        let [Message::Block(found), Message::NotFound(not_found)] = responses.as_slice() else {
            panic!("expected block plus notfound, got {responses:?}");
        };
        assert_eq!(found.block_hash(), chain.headers[0].compute_hash());
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

    /// Streaming chain fake mirroring `NodeP2pChainQuery`: block-typed items
    /// that resolve to a stored body are served behind `headroom`; all other
    /// items land in `not_found` without a load. Counters and the tripwire
    /// back the hostile-preload gates.
    struct StreamingChain {
        blocks: Vec<Block>,
        loads: AtomicUsize,
        headroom_calls: AtomicUsize,
        /// Panics when a load would reach this count (mutation-gate tripwire).
        load_tripwire: Option<usize>,
    }

    impl ChainQuery for StreamingChain {
        fn headers_after(
            &self,
            _locator_hashes: &[BlockHash],
            _stop_hash: BlockHash,
            _limit: usize,
        ) -> Vec<Header> {
            Vec::new()
        }

        fn serve_inventory_blocks(
            &self,
            items: &[Inventory],
            headroom: &dyn Fn() -> bool,
            serve: &mut dyn FnMut(Block) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            let mut outcome = InventoryServing::default();
            for item in items {
                let Some(hash) = inv_hash(item) else {
                    outcome.not_found.push(*item);
                    continue;
                };
                let Some(found) = self.blocks.iter().find(|block| wire_hash(block) == hash) else {
                    outcome.not_found.push(*item);
                    continue;
                };
                self.headroom_calls.fetch_add(1, Ordering::Relaxed);
                if !headroom() {
                    outcome.halted = true;
                    return Ok(outcome);
                }
                if let Some(limit) = self.load_tripwire {
                    assert!(
                        self.loads.load(Ordering::Relaxed) < limit,
                        "hostile getdata materialized beyond the derived bound"
                    );
                }
                self.loads.fetch_add(1, Ordering::Relaxed);
                serve(found.clone())?;
            }
            Ok(outcome)
        }
    }

    #[test]
    fn streamed_getdata_preserves_batch_wire_order() -> Result<(), PeerError> {
        let headers = FakeChain::with_headers(2).headers;
        let block_a = Block {
            header: headers[0],
            txs: Vec::new(),
        };
        let block_b = Block {
            header: headers[1],
            txs: Vec::new(),
        };
        let inv_a = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *headers[0].compute_hash().as_bytes(),
        ));
        let inv_b = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *headers[1].compute_hash().as_bytes(),
        ));
        let tx_inv = Inventory::Transaction(bitcoin::Txid::from_byte_array([1; 32]));
        let unknown = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([9; 32]));
        let chain = StreamingChain {
            blocks: vec![block_a.clone(), block_b.clone()],
            loads: AtomicUsize::new(0),
            headroom_calls: AtomicUsize::new(0),
            load_tripwire: None,
        };
        let mut peer = ready_peer();

        let emitted = dispatch_collect(
            &mut peer,
            &Message::GetData(vec![tx_inv, inv_a, inv_b, unknown]),
            Some(&chain),
        )?;

        assert_eq!(
            emitted,
            vec![
                Message::Block(block_a),
                Message::Block(block_b),
                Message::NotFound(vec![tx_inv, unknown]),
            ],
            "streamed emission must equal the pre-change batch shape (I8)"
        );
        assert_eq!(chain.loads.load(Ordering::Relaxed), 2);
        assert_eq!(chain.headroom_calls.load(Ordering::Relaxed), 2);
        Ok(())
    }

    #[test]
    fn headroom_false_before_first_load_halts_without_loading() {
        let headers = FakeChain::with_headers(1).headers;
        let block = Block {
            header: headers[0],
            txs: Vec::new(),
        };
        let known = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *headers[0].compute_hash().as_bytes(),
        ));
        let chain = StreamingChain {
            blocks: vec![block],
            loads: AtomicUsize::new(0),
            headroom_calls: AtomicUsize::new(0),
            load_tripwire: None,
        };
        let mut peer = ready_peer();
        let emitted = RefCell::new(Vec::new());

        let result = dispatch_inbound_with_chain(
            &mut peer,
            &Message::GetData(vec![known]),
            Some(&chain),
            &|| false,
            &mut |response| {
                emitted.borrow_mut().push(response);
                Ok(())
            },
        );

        assert!(matches!(
            result,
            Err(PeerError::Protocol(
                "getdata serving halted: outbound production gate",
            ))
        ));
        assert_eq!(chain.headroom_calls.load(Ordering::Relaxed), 1);
        assert_eq!(chain.loads.load(Ordering::Relaxed), 0);
        assert!(
            emitted.into_inner().is_empty(),
            "halt never emits a trailing notfound (I9)"
        );
    }

    fn wire_len_of(message: &Message) -> usize {
        crate::wire::wire_len(message).unwrap_or_else(|_| panic!("test message must encode"))
    }

    #[test]
    fn hostile_50000_item_getdata_cannot_materialize_unbounded_blocks() {
        let block = Block::default();
        let block_wire_len = wire_len_of(&Message::Block(block.clone()));
        // Zero-drain attacker: the outbound channel is never drained, so
        // every admitted message stays charged to the budget.
        let (outbound_tx, _undrained_rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new_with_budget(
            outbound_tx,
            false,
            OutboundBudget::with_block_reserve(100_000, 4 * 2 * block_wire_len, 2 * block_wire_len),
        );
        let budget = lease.budget_handle();
        let known = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *block.block_hash().as_bytes(),
        ));
        let chain = StreamingChain {
            blocks: vec![block],
            loads: AtomicUsize::new(0),
            headroom_calls: AtomicUsize::new(0),
            // B = 7 serves: the gate allows a load while
            // pending_bytes + reserve <= 4 * reserve with each served block
            // charging block_wire_len = reserve / 2. The tripwire fires on
            // the first bound-breaking load.
            load_tripwire: Some(8),
        };
        let mut peer = ready_peer();

        let result = dispatch_inbound_with_chain(
            &mut peer,
            &Message::GetData(vec![known; MAX_INV_PER_MSG]),
            Some(&chain),
            &|| budget.has_block_production_headroom(),
            &mut |message| {
                lease
                    .send(message)
                    .map_err(|_| PeerError::Protocol("outbound queue closed or saturated"))
            },
        );

        assert!(matches!(
            result,
            Err(PeerError::Protocol(
                "getdata serving halted: outbound production gate",
            ))
        ));
        assert_eq!(chain.loads.load(Ordering::Relaxed), 7);
        assert_eq!(chain.headroom_calls.load(Ordering::Relaxed), 8);
        assert_eq!(budget.pending(), (7, 7 * block_wire_len));
    }

    #[test]
    fn send_refusal_mid_stream_aborts_production() {
        let block = Block::default();
        let block_wire_len = wire_len_of(&Message::Block(block.clone()));
        let (outbound_tx, _undrained_rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new_with_budget(
            outbound_tx,
            false,
            OutboundBudget::with_block_reserve(100_000, 3 * block_wire_len, 0),
        );
        let budget = lease.budget_handle();
        let known = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
            *block.block_hash().as_bytes(),
        ));
        let chain = StreamingChain {
            blocks: vec![block.clone(), block.clone(), block.clone(), block],
            loads: AtomicUsize::new(0),
            headroom_calls: AtomicUsize::new(0),
            load_tripwire: None,
        };
        let mut peer = ready_peer();

        let result = dispatch_inbound_with_chain(
            &mut peer,
            &Message::GetData(vec![known; 4]),
            Some(&chain),
            &|| true,
            &mut |message| {
                lease
                    .send(message)
                    .map_err(|_| PeerError::Protocol("outbound queue closed or saturated"))
            },
        );

        assert!(matches!(
            result,
            Err(PeerError::Protocol("outbound queue closed or saturated"))
        ));
        assert_eq!(
            chain.loads.load(Ordering::Relaxed),
            4,
            "three admitted plus one refused load"
        );
        assert!(lease.is_cancelled());
        // The refused fourth block is dropped with the error, never queued.
        assert_eq!(budget.pending(), (3, 3 * block_wire_len));
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

    // --- TxInventory filter and getdata tx serving tests ---

    /// A fake `TxInventory` that knows a fixed set of txids/wtxids and can
    /// serve their bodies.
    struct FakeTxInventory {
        txs_by_txid: hashbrown::HashMap<bitcoin::Txid, Tx>,
        txs_by_wtxid: hashbrown::HashMap<bitcoin::Wtxid, Tx>,
        have_hashes: hashbrown::HashSet<[u8; 32]>,
    }

    impl FakeTxInventory {
        fn empty() -> Self {
            Self {
                txs_by_txid: hashbrown::HashMap::new(),
                txs_by_wtxid: hashbrown::HashMap::new(),
                have_hashes: hashbrown::HashSet::new(),
            }
        }

        fn with_tx(mut self, tx: Tx) -> Self {
            let txid = bitcoin::Txid::from_byte_array(*tx.txid().as_bytes());
            let wtxid = bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes());
            self.txs_by_txid.insert(txid, tx.clone());
            self.txs_by_wtxid.insert(wtxid, tx);
            self
        }

        fn with_have(mut self, hash: [u8; 32]) -> Self {
            self.have_hashes.insert(hash);
            self
        }
    }

    impl TxInventory for FakeTxInventory {
        fn have_tx(&self, hash: Hash256, _wtxid_relay: bool) -> bool {
            self.have_hashes.contains(hash.as_byte_array())
        }

        fn get_tx(&self, txid: Txid) -> Option<Tx> {
            let btid = bitcoin::Txid::from_byte_array(*txid.as_bytes());
            self.txs_by_txid.get(&btid).cloned()
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
            let bwid = bitcoin::Wtxid::from_byte_array(*wtxid.as_bytes());
            self.txs_by_wtxid.get(&bwid).cloned()
        }
    }

    fn dummy_tx(byte: u8) -> Tx {
        use bitcoin_rs_primitives::{OutPoint, TxIn, TxOut};
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                    vout: 0,
                },
                script_sig: vec![byte],
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x6A],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn inv_filter_suppresses_held_tx() {
        let tx = dummy_tx(1);
        let txid = tx.txid();
        let inv_tx = Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes()));
        let inventory = FakeTxInventory::empty().with_have(*txid.as_bytes());
        let mut peer = ready_peer();

        let responses = dispatch_collect_full(
            &mut peer,
            &Message::Inv(vec![inv_tx]),
            None,
            Some(&inventory),
        );

        assert!(
            responses.is_empty(),
            "inv for a held tx must produce no getdata"
        );
    }

    #[test]
    fn inv_filter_passes_unheld_tx() {
        let tx = dummy_tx(2);
        let txid = tx.txid();
        let inv_tx = Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes()));
        let inventory = FakeTxInventory::empty();
        let mut peer = ready_peer();

        let responses = dispatch_collect_full(
            &mut peer,
            &Message::Inv(vec![inv_tx]),
            None,
            Some(&inventory),
        );

        assert_eq!(
            responses,
            vec![Message::GetData(vec![inv_tx])],
            "inv for an unheld tx must produce a getdata"
        );
    }

    #[test]
    fn getdata_serves_held_tx_and_notfound_for_missing() {
        let tx = dummy_tx(3);
        let txid = tx.txid();
        let inv_held = Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes()));
        let inv_missing = Inventory::Transaction(bitcoin::Txid::from_byte_array([0xFF; 32]));
        let inventory = FakeTxInventory::empty().with_tx(tx);
        let mut peer = ready_peer();

        let responses = dispatch_collect_full(
            &mut peer,
            &Message::GetData(vec![inv_held, inv_missing]),
            None,
            Some(&inventory),
        );

        assert_eq!(responses.len(), 2, "expected tx + notfound");
        assert!(
            matches!(responses[0], Message::Tx(_)),
            "first response must be the held tx body"
        );
        assert_eq!(
            responses[1],
            Message::NotFound(vec![inv_missing]),
            "second response must be notfound for the missing tx"
        );
    }

    #[test]
    fn getdata_wtxid_serves_held_tx() {
        let tx = dummy_tx(4);
        let wtxid = tx.wtxid();
        let inv_wtx = Inventory::WTx(bitcoin::Wtxid::from_byte_array(*wtxid.as_bytes()));
        let inventory = FakeTxInventory::empty().with_tx(tx);
        let mut peer = ready_peer();

        let responses = dispatch_collect_full(
            &mut peer,
            &Message::GetData(vec![inv_wtx]),
            None,
            Some(&inventory),
        );

        assert_eq!(responses.len(), 1, "expected one tx response");
        assert!(
            matches!(responses[0], Message::Tx(_)),
            "wtxid-typed getdata for a held tx must serve its body"
        );
    }

    #[test]
    fn getdata_tx_without_inventory_reports_notfound() {
        let inv_tx = Inventory::Transaction(bitcoin::Txid::from_byte_array([1; 32]));
        let mut peer = ready_peer();

        let responses =
            dispatch_collect_full(&mut peer, &Message::GetData(vec![inv_tx]), None, None);

        assert_eq!(
            responses,
            vec![Message::NotFound(vec![inv_tx])],
            "getdata for tx without TxInventory must report notfound"
        );
    }

    #[test]
    fn inv_filter_bip339_wtxid() {
        let tx = dummy_tx(5);
        let wtxid = tx.wtxid();
        let inv_wtx = Inventory::WTx(bitcoin::Wtxid::from_byte_array(*wtxid.as_bytes()));
        let inventory = FakeTxInventory::empty().with_have(*wtxid.as_bytes());
        let mut peer = ready_peer();
        // Simulate BIP339 negotiation: peer advertised wtxid relay.
        peer.wtxid_relay.mark_peer_supported();

        let responses = dispatch_collect_full(
            &mut peer,
            &Message::Inv(vec![inv_wtx]),
            None,
            Some(&inventory),
        );

        assert!(
            responses.is_empty(),
            "BIP339 wtxid inv for a held tx must produce no getdata"
        );
    }

    #[allow(clippy::expect_used)]
    fn dispatch_collect_full<S>(
        peer: &mut Peer<S>,
        message: &Message,
        chain: Option<&dyn ChainQuery>,
        tx_inventory: Option<&dyn TxInventory>,
    ) -> Vec<Message> {
        let collected = RefCell::new(Vec::new());
        dispatch_inbound_full(
            peer,
            message,
            chain,
            tx_inventory,
            &|| true,
            &mut |response| {
                collected.borrow_mut().push(response);
                Ok(())
            },
        )
        .expect("dispatch must succeed");
        collected.into_inner()
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

    fn test_header(prev_blockhash: BlockHash, nonce: u32) -> Header {
        Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&[0; 32]),
            time: nonce,
            bits: 0x207f_ffff,
            nonce,
        }
    }
}
