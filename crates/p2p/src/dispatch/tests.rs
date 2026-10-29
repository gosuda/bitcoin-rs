use bitcoin_rs_consensus::ValidationEngine;
use std::cell::RefCell;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest};
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
use bitcoin::p2p::message_compact_blocks::BlockTxn;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Sequence, Tx, Txid,
    Witness, Wtxid, deserialize,
};

use super::{
    ChainQuery, FilterRequest, FilterServing, InventoryServing, MAX_LOCATOR_HASHES,
    StaleTipHeaders, TxInventory, dispatch_inbound, dispatch_inbound_full, serve_getdata,
};
use crate::connection::{OutboundBudget, PeerLease};
use crate::feature::{FEATURE_VERSION, FeatureAnnouncement, FeatureId};
use crate::handshake::{feature_messages, negotiated_features};
use crate::inv::MAX_INV_PER_MSG;
use crate::packages::{
    AncPkgInfo, GetPkgTxns, MSG_ANCPKGINFO, MSG_PKGTXNS, PKG_RELAY_ANC, PKG_RELAY_PKGTXNS, PkgTxns,
    SendPackages, combined_package_hash,
};
use crate::peer::{PackageRequest, Peer, PeerState};
use crate::wire::{MAX_HEADERS_MESSAGE_COUNT, Message, PROTOCOL_VERSION, PeerError};

fn block_payload(block: &Block) -> Message {
    Message::BlockPayload(bytes::Bytes::from(bitcoin_rs_primitives::consensus_bytes(
        block,
    )))
}

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
    fn stale_tip_announcement(
        &self,
        _tip: Hash256,
        _peer_tips: &[Hash256],
    ) -> Option<StaleTipHeaders> {
        None
    }
    fn serve_compact_filters(
        &self,
        request: &FilterRequest,
        _: &dyn Fn() -> bool,
        _: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<FilterServing, PeerError> {
        Ok(FilterServing::Pending(request.clone()))
    }
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
        _compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
        serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
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
            serve(block_payload(found))?;
        }
        Ok(outcome)
    }

    fn block_transactions(
        &self,
        _request: &BlockTransactionsRequest,
        _compact_version: Option<u64>,
        _headroom: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError> {
        Ok(None)
    }
}

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
    fn stale_tip_announcement(
        &self,
        _tip: Hash256,
        _peer_tips: &[Hash256],
    ) -> Option<StaleTipHeaders> {
        None
    }
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
        _compact_version: Option<u64>,
        _headroom: &dyn Fn() -> bool,
        _serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError> {
        Ok(InventoryServing::default())
    }

    fn block_transactions(
        &self,
        _request: &BlockTransactionsRequest,
        _compact_version: Option<u64>,
        _headroom: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError> {
        Ok(None)
    }
}

fn dispatch_collect<S>(
    peer: &mut Peer<S>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
) -> Result<Vec<Message>, PeerError> {
    let collected = RefCell::new(Vec::new());
    dispatch_inbound_full(
        peer,
        message,
        chain,
        None,
        &|| true,
        &|| true,
        &mut |response| {
            collected.borrow_mut().push(response);
            Ok(())
        },
        &mut |_| {},
        &mut |items| collected.borrow_mut().push(Message::GetData(items)),
    )?;
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
    let count = u32::try_from(MAX_HEADERS_MESSAGE_COUNT + 1)
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
    assert_eq!(headers.len(), MAX_HEADERS_MESSAGE_COUNT);
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
        Err(PeerError::Misbehavior("getheaders locator too large"))
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
        Err(PeerError::Misbehavior("getblocks locator too large"))
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

    assert_eq!(responses, []);
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

    let [Message::BlockPayload(found), Message::NotFound(not_found)] = responses.as_slice() else {
        panic!("expected block payload plus notfound, got {responses:?}");
    };
    let found = deserialize::<Block>(found)
        .unwrap_or_else(|error| panic!("served payload must decode: {error}"));
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

#[test]
fn getblocktxn_is_answered_with_blocktxn_from_the_chain() -> Result<(), PeerError> {
    struct ServingChain;
    impl ChainQuery for ServingChain {
        fn stale_tip_announcement(
            &self,
            _tip: Hash256,
            _peer_tips: &[Hash256],
        ) -> Option<StaleTipHeaders> {
            None
        }
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
            _items: &[Inventory],
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
            _serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            Ok(InventoryServing::default())
        }

        fn block_transactions(
            &self,
            request: &BlockTransactionsRequest,
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
        ) -> Result<Option<Message>, PeerError> {
            Ok(Some(Message::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: request.block_hash,
                    transactions: Vec::new(),
                },
            })))
        }
    }

    let mut peer = ready_peer();
    let responses = dispatch_collect(
        &mut peer,
        &Message::GetBlockTxn(bitcoin::p2p::message_compact_blocks::GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: bitcoin::BlockHash::from_byte_array([7; 32]),
                indexes: vec![0],
            },
        }),
        Some(&ServingChain),
    )?;

    assert!(matches!(responses.as_slice(), [Message::BlockTxn(_)]));
    Ok(())
}

fn assert_getblocktxn_refused(indexes: Vec<u64>) {
    let chain = FakeChain::with_headers(2);
    let message = Message::GetBlockTxn(bitcoin::p2p::message_compact_blocks::GetBlockTxn {
        txs_request: BlockTransactionsRequest {
            block_hash: bitcoin::BlockHash::from_byte_array([7; 32]),
            indexes,
        },
    });
    let view: &dyn ChainQuery = &chain;
    for case in [Some(view), None] {
        let mut peer = ready_peer();
        let outcome = dispatch_collect(&mut peer, &message, case);
        assert!(
            matches!(outcome, Err(PeerError::Misbehavior(_))),
            "a malformed getblocktxn must disconnect, got {outcome:?}",
        );
    }
}

#[test]
fn invalid_getblocktxn_indexes_disconnect() {
    assert_getblocktxn_refused(Vec::new());
    assert_getblocktxn_refused(vec![1, 1]);
    assert_getblocktxn_refused(vec![3, 2]);
}

#[test]
fn getblocktxn_is_unanswered_while_the_production_gate_is_saturated()
-> Result<(), Box<dyn std::error::Error>> {
    struct GatedChain {
        observed: AtomicUsize,
        loads: AtomicUsize,
    }
    impl ChainQuery for GatedChain {
        fn stale_tip_announcement(
            &self,
            _tip: Hash256,
            _peer_tips: &[Hash256],
        ) -> Option<StaleTipHeaders> {
            None
        }
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
            _items: &[Inventory],
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
            _serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
        ) -> Result<InventoryServing, PeerError> {
            Ok(InventoryServing::default())
        }

        fn block_transactions(
            &self,
            request: &BlockTransactionsRequest,
            _compact_version: Option<u64>,
            headroom: &dyn Fn() -> bool,
        ) -> Result<Option<Message>, PeerError> {
            self.observed.fetch_add(1, Ordering::Relaxed);
            if !headroom() {
                return Ok(None);
            }
            self.loads.fetch_add(1, Ordering::Relaxed);
            Ok(Some(Message::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: request.block_hash,
                    transactions: Vec::new(),
                },
            })))
        }
    }

    let chain = GatedChain {
        observed: AtomicUsize::new(0),
        loads: AtomicUsize::new(0),
    };
    let message = Message::GetBlockTxn(bitcoin::p2p::message_compact_blocks::GetBlockTxn {
        txs_request: BlockTransactionsRequest {
            block_hash: bitcoin::BlockHash::from_byte_array([7; 32]),
            indexes: vec![0],
        },
    });
    let mut peer = ready_peer();
    let collected = RefCell::new(Vec::new());
    dispatch_inbound_full(
        &mut peer,
        &message,
        Some(&chain),
        None,
        &|| true,
        &|| false,
        &mut |response| {
            collected.borrow_mut().push(response);
            Ok(())
        },
        &mut |_| {},
        &mut |items| collected.borrow_mut().push(Message::GetData(items)),
    )?;

    assert_eq!(chain.observed.load(Ordering::Relaxed), 1);
    assert_eq!(
        chain.loads.load(Ordering::Relaxed),
        0,
        "a saturated gate must not produce a reply body"
    );
    assert!(
        collected.borrow().is_empty(),
        "the request stays unanswered"
    );
    Ok(())
}

struct StreamingChain {
    blocks: Vec<Block>,
    loads: AtomicUsize,
    headroom_calls: AtomicUsize,
    load_tripwire: Option<usize>,
}
impl ChainQuery for StreamingChain {
    fn stale_tip_announcement(
        &self,
        _tip: Hash256,
        _peer_tips: &[Hash256],
    ) -> Option<StaleTipHeaders> {
        None
    }
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
        _compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
        serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
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
            serve(block_payload(found))?;
        }
        Ok(outcome)
    }

    fn block_transactions(
        &self,
        _request: &BlockTransactionsRequest,
        _compact_version: Option<u64>,
        _headroom: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError> {
        Ok(None)
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
            block_payload(&block_a),
            block_payload(&block_b),
            Message::NotFound(vec![tx_inv, unknown]),
        ],
        "streamed emission must equal the pre-change batch shape (I8)"
    );
    assert_eq!(chain.loads.load(Ordering::Relaxed), 2);
    assert_eq!(chain.headroom_calls.load(Ordering::Relaxed), 2);
    Ok(())
}

#[test]
fn headroom_false_before_first_load_parks_without_loading() {
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

    let result = dispatch_inbound_full(
        &mut peer,
        &Message::GetData(vec![known]),
        Some(&chain),
        None,
        &|| true,
        &|| false,
        &mut |response| {
            emitted.borrow_mut().push(response);
            Ok(())
        },
        &mut |_| {},
        &mut |_| {},
    );

    assert!(
        result.is_ok(),
        "a saturated gate parks the request instead of failing the peer"
    );
    assert_eq!(chain.headroom_calls.load(Ordering::Relaxed), 1);
    assert_eq!(chain.loads.load(Ordering::Relaxed), 0);
    assert!(
        emitted.into_inner().is_empty(),
        "halt never emits a trailing notfound (I9)"
    );
    assert_eq!(peer.pending_getdata, vec![known]);
    assert_eq!(peer.pending_notfound, Vec::new());
}

fn wire_len_of(message: &Message) -> usize {
    crate::wire::wire_len(message).unwrap_or_else(|_| panic!("test message must encode"))
}

#[test]
fn hostile_50000_item_getdata_parks_the_tail() {
    let block = Block::default();
    let block_wire_len = wire_len_of(&block_payload(&block));
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
        load_tripwire: Some(8),
    };
    let mut peer = ready_peer();

    let result = dispatch_inbound_full(
        &mut peer,
        &Message::GetData(vec![known; MAX_INV_PER_MSG]),
        Some(&chain),
        None,
        &|| true,
        &|| budget.may_reserve_production(),
        &mut |message| {
            lease
                .send(message)
                .map_err(|_| PeerError::Protocol("outbound queue closed or saturated"))
        },
        &mut |_| {},
        &mut |_| {},
    );

    assert!(result.is_ok(), "a saturated gate parks the tail");
    assert_eq!(chain.loads.load(Ordering::Relaxed), 7);
    assert_eq!(chain.headroom_calls.load(Ordering::Relaxed), 8);
    assert_eq!(budget.pending(), (7, 7 * block_wire_len));
    assert_eq!(peer.pending_getdata.len(), MAX_INV_PER_MSG - 7);
    assert_eq!(peer.pending_notfound, Vec::new());
    assert!(!lease.is_cancelled(), "parking never cancels the lease");
}

#[test]
fn halted_mixed_getdata_parks_ordered_tail_and_unsent_misses() -> Result<(), PeerError> {
    let headers = FakeChain::with_headers(2).headers;
    let block_a = Block {
        header: headers[0],
        txs: Vec::new(),
    };
    let block_b = Block {
        header: headers[1],
        txs: Vec::new(),
    };
    let inv_a = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(wire_hash(&block_a)));
    let inv_b = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(wire_hash(&block_b)));
    let held = dummy_tx(1);
    let tx_hit =
        Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*held.txid().as_bytes()));
    let tx_miss = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([7; 32]));
    let unknown_block = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([9; 32]));
    let inventory = FakeTxInventory::empty().with_tx(held.clone());
    let chain = StreamingChain {
        blocks: vec![block_a.clone(), block_b.clone()],
        loads: AtomicUsize::new(0),
        headroom_calls: AtomicUsize::new(0),
        load_tripwire: None,
    };
    let mut peer = ready_peer();
    let emitted = RefCell::new(Vec::new());
    let consulted = std::cell::Cell::new(0_usize);

    dispatch_inbound_full(
        &mut peer,
        &Message::GetData(vec![tx_miss, inv_a, tx_hit, inv_b, unknown_block]),
        Some(&chain),
        Some(&inventory),
        &|| true,
        &|| {
            consulted.set(consulted.get() + 1);
            consulted.get() <= 2
        },
        &mut |response| {
            emitted.borrow_mut().push(response);
            Ok(())
        },
        &mut |_| {},
        &mut |_| {},
    )?;

    assert_eq!(
        emitted.take(),
        vec![block_payload(&block_a)],
        "only what was served before the gate closed is on the wire"
    );
    assert_eq!(peer.pending_notfound, vec![tx_miss]);
    assert_eq!(peer.pending_getdata, vec![tx_hit, inv_b, unknown_block]);

    let mut misses = Vec::new();
    let rest = serve_getdata(
        Some(&chain),
        Some(&inventory),
        None,
        &peer.pending_getdata,
        &mut misses,
        &|| true,
        &mut |response| {
            emitted.borrow_mut().push(response);
            Ok(())
        },
    )?;

    assert!(rest.is_empty(), "an open gate finishes the tail");
    assert_eq!(
        emitted.take(),
        vec![
            Message::Tx(held),
            block_payload(&block_b),
            Message::NotFound(vec![unknown_block]),
        ],
        "the resumed tail keeps request order and ends in one notfound"
    );
    assert!(
        misses.is_empty(),
        "the trailing notfound drained the misses when the gate stayed open"
    );
    Ok(())
}

#[test]
fn gate_closed_at_the_trailing_report_parks_the_misses() -> Result<(), PeerError> {
    let headers = FakeChain::with_headers(1).headers;
    let block = Block {
        header: headers[0],
        txs: Vec::new(),
    };
    let served = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
        *headers[0].compute_hash().as_bytes(),
    ));
    let miss = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([6; 32]));
    let chain = StreamingChain {
        blocks: vec![block.clone()],
        loads: AtomicUsize::new(0),
        headroom_calls: AtomicUsize::new(0),
        load_tripwire: None,
    };
    let inventory = FakeTxInventory::empty();
    let emitted = RefCell::new(Vec::new());
    let consulted = std::cell::Cell::new(0_usize);
    let mut not_found = Vec::new();

    let tail = serve_getdata(
        Some(&chain),
        Some(&inventory),
        None,
        &[miss, served],
        &mut not_found,
        &|| {
            consulted.set(consulted.get() + 1);
            consulted.get() <= 2
        },
        &mut |response| {
            emitted.borrow_mut().push(response);
            Ok(())
        },
    )?;

    assert!(tail.is_empty(), "the whole request was handled");
    assert_eq!(
        emitted.into_inner(),
        vec![block_payload(&block)],
        "the block was served while the gate was open"
    );
    assert_eq!(
        not_found,
        vec![miss],
        "the trailing report must keep the misses parked, unsent"
    );
    Ok(())
}

#[test]
fn getdata_while_one_is_parked_is_refused_and_keeps_the_tail() {
    let parked = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([4; 32]));
    let mut peer = ready_peer();
    peer.pending_getdata = vec![parked];
    let emitted = RefCell::new(Vec::new());

    let result = dispatch_inbound_full(
        &mut peer,
        &Message::GetData(vec![Inventory::WitnessBlock(
            bitcoin::BlockHash::from_byte_array([5; 32]),
        )]),
        None,
        None,
        &|| true,
        &|| true,
        &mut |response| {
            emitted.borrow_mut().push(response);
            Ok(())
        },
        &mut |_| {},
        &mut |_| {},
    );

    assert!(matches!(result, Err(PeerError::Io(_))));
    assert_eq!(
        peer.pending_getdata,
        vec![parked],
        "the earlier tail survives"
    );
    assert_eq!(emitted.into_inner(), Vec::new());
}

#[test]
fn send_refusal_mid_stream_aborts_production() {
    let block = Block::default();
    let block_wire_len = wire_len_of(&block_payload(&block));
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

    let result = dispatch_inbound_full(
        &mut peer,
        &Message::GetData(vec![known; 4]),
        Some(&chain),
        None,
        &|| true,
        &|| true,
        &mut |message| {
            lease
                .send(message)
                .map_err(|_| PeerError::Protocol("outbound queue closed or saturated"))
        },
        &mut |_| {},
        &mut |_| {},
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
        Err(PeerError::Misbehavior("getdata inventory too large"))
    ));
    assert_eq!(peer_snapshot(&peer), before);
}

struct FakeTxInventory {
    txs_by_txid: hashbrown::HashMap<bitcoin::Txid, Tx>,
    txs_by_wtxid: hashbrown::HashMap<bitcoin::Wtxid, Tx>,
    have_hashes: hashbrown::HashSet<[u8; 32]>,
    resident: Vec<Arc<Tx>>,
    ancestor_packages: hashbrown::HashMap<Wtxid, Vec<Wtxid>>,
}

impl FakeTxInventory {
    fn empty() -> Self {
        Self {
            txs_by_txid: hashbrown::HashMap::new(),
            txs_by_wtxid: hashbrown::HashMap::new(),
            have_hashes: hashbrown::HashSet::new(),
            resident: Vec::new(),
            ancestor_packages: hashbrown::HashMap::new(),
        }
    }

    fn with_resident_tx(mut self, tx: Tx) -> Self {
        self.resident.push(Arc::new(tx.clone()));
        self.with_tx(tx)
    }

    fn with_ancestor_package(mut self, subject: Wtxid, package: Vec<Wtxid>) -> Self {
        self.ancestor_packages.insert(subject, package);
        self
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
    fn have_tx(&self, hash: Hash256, _hash_is_wtxid: bool) -> bool {
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

    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>> {
        self.ancestor_packages.get(&wtxid).cloned()
    }

    fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
        wtxids
            .iter()
            .map(|wtxid| {
                self.resident
                    .iter()
                    .find(|tx| tx.wtxid() == *wtxid)
                    .map(Arc::clone)
            })
            .collect()
    }
}

fn dummy_tx(byte: u8) -> Tx {
    use bitcoin_rs_primitives::{OutPoint, TxIn, TxOut, Witness};
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                vout: 0,
            },
            script_sig: vec![byte].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x6A].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

#[test]
fn getdata_completes_initial_broadcast_only_after_successful_send()
-> Result<(), Box<dyn std::error::Error>> {
    use super::serve_getdata;
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_mempool::{
        AdmissionOrigin, Mempool, MempoolEntry, MempoolGateway, MempoolLimits,
    };
    use bitcoin_rs_primitives::Witness;
    use std::sync::Arc;
    for kind in 0..3 {
        let gateway = MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(
                MempoolLimits::default(),
            ))),
            None,
            ValidationEngine::Native,
            None,
        );
        let mut tx = dummy_tx(1);
        tx.inputs[0].witness = Witness::from_stack(vec![vec![0x51]]);
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        gateway.insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(tx), 100, 1000, 1, 0, 0),
        )?;
        let sequence = gateway.read().sequence_number();
        let item = match kind {
            0 => Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())),
            1 => Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())),
            _ => Inventory::WTx(bitcoin::Wtxid::from_byte_array(*wtxid.as_bytes())),
        };
        let mut not_found = Vec::new();
        assert!(
            serve_getdata(
                None,
                Some(&gateway),
                None,
                &[item],
                &mut not_found,
                &|| true,
                &mut |_| Err(PeerError::Misbehavior("test sink full"))
            )
            .is_err()
        );
        assert_eq!(gateway.read().unbroadcast_transactions().count(), 1);
        let mut responses = Vec::new();
        serve_getdata(
            None,
            Some(&gateway),
            None,
            &[item],
            &mut not_found,
            &|| true,
            &mut |message| {
                responses.push(message);
                Ok(())
            },
        )?;
        assert!(matches!(responses.as_slice(), [Message::Tx(_)]));
        assert_eq!(gateway.read().unbroadcast_transactions().count(), 0);
        assert_eq!(gateway.read().sequence_number(), sequence);
    }
    Ok(())
}

#[test]
fn announced_transactions_request_witness_without_changing_hashes() {
    let inventory = FakeTxInventory::empty();
    for witness in [false, true] {
        for filtered in [false, true] {
            let mut peer = ready_peer();
            let mut version = crate::handshake::version_message(
                1,
                0,
                crate::peer_info::PeerRole::FullRelay,
                bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
            );
            version.services = if witness {
                bitcoin::p2p::ServiceFlags::WITNESS
            } else {
                bitcoin::p2p::ServiceFlags::NETWORK
            };
            peer.remote_version = Some(version);
            let txid = bitcoin::Txid::from_byte_array([1; 32]);
            let wtxid = Inventory::WTx(bitcoin::Wtxid::from_byte_array([2; 32]));
            let block_hash = bitcoin::BlockHash::from_byte_array([3; 32]);
            let block = Inventory::Block(block_hash);
            let requested_tx = if witness {
                Inventory::WitnessTransaction(txid)
            } else {
                Inventory::Transaction(txid)
            };
            let view: Option<&dyn TxInventory> = filtered.then_some(&inventory);
            let (responses, announced) = dispatch_collect_announcements(
                &mut peer,
                &Message::Inv(vec![Inventory::Transaction(txid), wtxid, block]),
                None,
                view,
                true,
            );
            assert_eq!(
                responses,
                vec![Message::GetData(vec![requested_tx, wtxid])],
                "announced transactions keep their witness serialization and \
                     no block body is requested"
            );
            assert_eq!(announced, vec![announced_hash(block_hash)]);
        }
    }
}

#[test]
fn inv_tx_vectors_not_requested_while_tx_relay_closed() {
    let txid = bitcoin::Txid::from_byte_array([1; 32]);
    let wtxid = Inventory::WTx(bitcoin::Wtxid::from_byte_array([2; 32]));
    let block_hash = bitcoin::BlockHash::from_byte_array([3; 32]);
    let block = Inventory::Block(block_hash);

    let mut peer = ready_peer();
    let (gated, announced) = dispatch_collect_announcements(
        &mut peer,
        &Message::Inv(vec![Inventory::Transaction(txid), wtxid, block]),
        None,
        None,
        false,
    );
    assert!(
        gated.is_empty(),
        "a closed relay gate must request no announced vector"
    );
    assert_eq!(
        announced,
        vec![announced_hash(block_hash)],
        "the block is announced to header sync either way"
    );

    let mut peer = ready_peer();
    let (open, announced) = dispatch_collect_announcements(
        &mut peer,
        &Message::Inv(vec![Inventory::Transaction(txid), wtxid, block]),
        None,
        None,
        true,
    );
    assert_eq!(
        open,
        vec![Message::GetData(vec![Inventory::Transaction(txid), wtxid])],
        "an open relay gate must request every announced tx"
    );
    assert_eq!(announced, vec![announced_hash(block_hash)]);
}

#[test]
fn inv_wtx_vectors_not_requested_while_tx_relay_closed() {
    let inventory = FakeTxInventory::empty();
    let wtxid = Inventory::WTx(bitcoin::Wtxid::from_byte_array([2; 32]));
    let witness_txid = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([1; 32]));
    let block_hash = bitcoin::BlockHash::from_byte_array([3; 32]);
    let block = Inventory::Block(block_hash);

    let mut peer = ready_peer();
    let (responses, announced) = dispatch_collect_announcements(
        &mut peer,
        &Message::Inv(vec![witness_txid, wtxid, block]),
        None,
        Some(&inventory),
        false,
    );
    assert!(
        responses.is_empty(),
        "a closed relay gate must suppress txid and wtxid vectors the node does not hold"
    );
    assert_eq!(announced, vec![announced_hash(block_hash)]);
}

#[test]
fn inv_block_uses_headers_not_body_getdata() {
    let block_hash = bitcoin::BlockHash::from_byte_array([3; 32]);
    for relay_open in [false, true] {
        for witness in [false, true] {
            let mut peer = ready_peer();
            let mut version = crate::handshake::version_message(
                1,
                0,
                crate::peer_info::PeerRole::FullRelay,
                bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
            );
            version.services = if witness {
                bitcoin::p2p::ServiceFlags::WITNESS
            } else {
                bitcoin::p2p::ServiceFlags::NETWORK
            };
            peer.remote_version = Some(version);
            let (responses, announced) = dispatch_collect_announcements(
                &mut peer,
                &Message::Inv(vec![
                    Inventory::Block(block_hash),
                    Inventory::WitnessBlock(block_hash),
                ]),
                None,
                None,
                relay_open,
            );
            assert!(
                responses.is_empty(),
                "block inventory must not emit a body getdata"
            );
            assert_eq!(
                announced,
                vec![announced_hash(block_hash); 2],
                "both block flavors reach the announcement sink"
            );
        }
    }
}

#[test]
fn gateway_inventory_filters_and_serves_txid_and_wtxid() {
    use std::sync::Arc;

    use bitcoin_rs_mempool::{
        AdmissionOrigin, Mempool, MempoolEntry, MempoolGateway, MempoolLimits,
    };
    use parking_lot::RwLock;

    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        None,
        ValidationEngine::Native,
        None,
    );
    let mut tx = dummy_tx(0x42);
    tx.inputs[0].witness = Witness::from_stack(vec![vec![0x01]]);
    let txid_item = Inventory::Transaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
    let witness_txid_item =
        Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
    let wtxid_item = Inventory::WTx(bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes()));
    assert_ne!(tx.txid().as_bytes(), tx.wtxid().as_bytes());
    assert!(
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(tx.clone()), 100, 10_000, 1, 0, 0),
            )
            .is_ok()
    );

    for (item, wtxid_relay) in [(txid_item, false), (wtxid_item, true)] {
        let mut peer = ready_peer();
        if wtxid_relay {
            peer.wtxid_relay.mark_peer_supported();
        }
        assert_eq!(
            dispatch_collect_full(&mut peer, &Message::Inv(vec![item]), None, Some(&gateway),),
            []
        );
    }

    let mut stripped = tx.clone();
    for input in &mut stripped.inputs {
        input.witness.clear();
    }
    let missing = Inventory::WTx(bitcoin::Wtxid::from_byte_array([0xFF; 32]));
    let mut peer = ready_peer();
    peer.wtxid_relay.mark_peer_supported();
    assert_eq!(
        dispatch_collect_full(
            &mut peer,
            &Message::GetData(vec![txid_item, witness_txid_item, wtxid_item, missing]),
            None,
            Some(&gateway),
        ),
        vec![
            Message::Tx(stripped),
            Message::Tx(tx.clone()),
            Message::Tx(tx.clone()),
            Message::NotFound(vec![missing])
        ],
    );
    assert_eq!(gateway.get_tx_by_wtxid(tx.wtxid()), Some(tx));
}

#[test]
#[expect(clippy::too_many_lines)]
fn one_sided_wtxid_negotiation_does_not_rerequest_pool_or_orphan_bodies() {
    use bitcoin_rs_primitives::Script;
    use std::sync::Arc;

    use bitcoin_rs_mempool::{
        AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolEntry,
        MempoolGateway, MempoolLimits, PeerToken, SubmitOutcome,
    };
    use parking_lot::RwLock;

    struct MissingCoins;
    impl AdmissionChain for MissingCoins {
        fn snapshot(&self, _tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            Some(ChainAdmissionSnapshot {
                prevouts: Vec::new(),
                height: 0,
                locktime_cutoff: 0,
                prevout_meta: hashbrown::HashMap::new(),
                csv_active: false,
                ..ChainAdmissionSnapshot::default()
            })
        }
    }

    for orphan in [false, true] {
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        );
        let mut tx = dummy_tx(0x51);
        tx.inputs[0].script_sig.clear();
        tx.inputs[0].witness = Witness::from_stack(vec![vec![0x51]]);
        tx.outputs[0].script_pubkey = Script::from_bytes(vec![0x6a, 4, 1, 2, 3, 4]);
        let tx = Arc::new(tx);
        let txid = bitcoin::Txid::from_byte_array(*tx.txid().as_bytes());
        let wtxid = bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes());
        assert_ne!(txid.as_byte_array(), wtxid.as_byte_array());
        if orphan {
            let source = PeerToken {
                endpoint: Some(bitcoin_rs_primitives::PeerEndpoint::Ip(
                    std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
                )),
                addr: Some(bitcoin_rs_primitives::PeerEndpoint::from((
                    [127, 0, 0, 1],
                    8333,
                ))),
                connection_id: 1,
            };
            assert!(matches!(
                gateway.submit_transaction(
                    Arc::clone(&tx),
                    AdmissionOrigin::Peer(source),
                    None,
                    0,
                    &MissingCoins,
                ),
                Ok(SubmitOutcome::Held { .. })
            ));
            assert_eq!(gateway.orphan_count(), 1);
            assert_eq!(
                gateway.get_tx_by_wtxid(tx.wtxid()).as_ref(),
                Some(tx.as_ref())
            );
        } else {
            assert!(
                gateway
                    .insert_entry(
                        AdmissionOrigin::Rpc,
                        MempoolEntry::new(Arc::clone(&tx), 100, 10_000, 1, 0, 0),
                    )
                    .is_ok()
            );
        }
        for (remote_requested, item) in [
            (false, Inventory::WTx(wtxid)),
            (true, Inventory::Transaction(txid)),
            (true, Inventory::WitnessTransaction(txid)),
        ] {
            let mut peer = ready_peer();
            if remote_requested {
                peer.wtxid_relay.mark_peer_supported();
            }
            let held_suppresses = !orphan || matches!(item, Inventory::WTx(_));
            let responses =
                dispatch_collect_full(&mut peer, &Message::Inv(vec![item]), None, Some(&gateway));
            if held_suppresses {
                assert!(
                    responses.is_empty(),
                    "inventory type must select the held body's identity in either relay direction"
                );
            } else {
                assert_eq!(responses, vec![Message::GetData(vec![item])]);
            }

            let unknown = Inventory::WTx(bitcoin::Wtxid::from_byte_array([0xff; 32]));
            let expected = if held_suppresses {
                vec![unknown]
            } else {
                vec![item, unknown]
            };
            assert_eq!(
                dispatch_collect_full(
                    &mut peer,
                    &Message::Inv(vec![item, unknown]),
                    None,
                    Some(&gateway),
                ),
                vec![Message::GetData(expected)]
            );
        }
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

    let responses = dispatch_collect_full(&mut peer, &Message::GetData(vec![inv_tx]), None, None);

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

fn announced_hash(block_hash: bitcoin::BlockHash) -> Hash256 {
    use bitcoin::hashes::Hash as _;
    Hash256::from_le_bytes(block_hash.as_byte_array())
}

fn dispatch_collect_full<S>(
    peer: &mut Peer<S>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
) -> Vec<Message> {
    dispatch_collect_gated(peer, message, chain, tx_inventory, true)
}

fn dispatch_collect_gated<S>(
    peer: &mut Peer<S>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
    relay_open: bool,
) -> Vec<Message> {
    dispatch_collect_announcements(peer, message, chain, tx_inventory, relay_open).0
}

#[expect(clippy::expect_used)]
fn dispatch_collect_announcements<S>(
    peer: &mut Peer<S>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
    relay_open: bool,
) -> (Vec<Message>, Vec<Hash256>) {
    let collected = RefCell::new(Vec::new());
    let mut announced = Vec::new();
    dispatch_inbound_full(
        peer,
        message,
        chain,
        tx_inventory,
        &|| relay_open,
        &|| true,
        &mut |response| {
            collected.borrow_mut().push(response);
            Ok(())
        },
        &mut |hash| announced.push(hash),
        &mut |items| collected.borrow_mut().push(Message::GetData(items)),
    )
    .expect("dispatch must succeed");
    (collected.into_inner(), announced)
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

#[test]
fn deferred_filter_request_keeps_ping_responsive_and_bounds_pending_work() -> Result<(), PeerError>
{
    let mut peer = ready_peer();
    let chain = FakeChain::default();
    let request = Message::GetCFilters(bitcoin::p2p::message_filter::GetCFilters {
        filter_type: 0,
        start_height: 0,
        stop_hash: bitcoin::BlockHash::all_zeros(),
    });
    let dispatch = |peer: &mut Peer<Cursor<Vec<u8>>>| {
        dispatch_inbound_full(
            peer,
            &request,
            Some(&chain),
            None,
            &|| true,
            &|| true,
            &mut |_| panic!("index not published"),
            &mut |_| {},
            &mut |_| {},
        )
    };
    dispatch(&mut peer)?;
    assert!(peer.pending_filter_request.is_some());
    assert_eq!(
        dispatch_inbound(&mut peer, &Message::Ping(42))?,
        vec![Message::Pong(42)]
    );
    assert!(matches!(dispatch(&mut peer), Err(PeerError::Io(_))));
    Ok(())
}

struct NarrowingChain;

impl ChainQuery for NarrowingChain {
    fn stale_tip_announcement(
        &self,
        _tip: Hash256,
        _peer_tips: &[Hash256],
    ) -> Option<StaleTipHeaders> {
        None
    }
    fn serve_compact_filters(
        &self,
        request: &FilterRequest,
        _: &dyn Fn() -> bool,
        send: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<FilterServing, PeerError> {
        let Message::GetCFilters(first) = &request.request else {
            return Ok(FilterServing::Done);
        };
        send(Message::Pong(u64::from(first.start_height)))?;
        Ok(FilterServing::Pending(FilterRequest {
            request: Message::GetCFilters(bitcoin::p2p::message_filter::GetCFilters {
                filter_type: first.filter_type,
                start_height: first.start_height + 1,
                stop_hash: first.stop_hash,
            }),
            expected_end: Some(9),
        }))
    }

    fn headers_after(&self, _: &[BlockHash], _: BlockHash, _: usize) -> Vec<Header> {
        Vec::new()
    }

    fn serve_inventory_blocks(
        &self,
        _: &[Inventory],
        _: Option<u64>,
        _: &dyn Fn() -> bool,
        _: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError> {
        Ok(InventoryServing::default())
    }

    fn block_transactions(
        &self,
        _: &BlockTransactionsRequest,
        _: Option<u64>,
        _: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError> {
        Ok(None)
    }
}

#[test]
fn filter_remainder_is_the_parked_requests_only_cursor() -> Result<(), PeerError> {
    let mut peer = ready_peer();
    let request = Message::GetCFilters(bitcoin::p2p::message_filter::GetCFilters {
        filter_type: 0,
        start_height: 3,
        stop_hash: bitcoin::BlockHash::all_zeros(),
    });
    let mut sent = Vec::new();

    dispatch_inbound_full(
        &mut peer,
        &request,
        Some(&NarrowingChain),
        None,
        &|| true,
        &|| true,
        &mut |message| {
            sent.push(message);
            Ok(())
        },
        &mut |_| {},
        &mut |_| {},
    )?;

    assert_eq!(sent, vec![Message::Pong(3)]);
    let parked = peer
        .pending_filter_request
        .as_ref()
        .ok_or(PeerError::Protocol("the remainder was not parked"))?;
    assert_eq!(
        parked.pending,
        FilterRequest {
            request: Message::GetCFilters(bitcoin::p2p::message_filter::GetCFilters {
                filter_type: 0,
                start_height: 4,
                stop_hash: bitcoin::BlockHash::all_zeros(),
            }),
            expected_end: Some(9),
        }
    );
    Ok(())
}

fn version_at(version: u32) -> Message {
    Message::Version(bitcoin::p2p::message_network::VersionMessage {
        version,
        ..crate::handshake::version_message(
            1,
            0,
            crate::peer_info::PeerRole::FullRelay,
            bitcoin::p2p::ServiceFlags::NETWORK,
        )
    })
}

/// below BIP434's version never receives a `feature` frame.
#[test]
fn version_reply_orders_features_between_feature_messages_and_verack() -> Result<(), PeerError> {
    for version in [FEATURE_VERSION - 1, PROTOCOL_VERSION] {
        let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
        peer.offer_stale_tip_relay(true);

        let responses = dispatch_inbound(&mut peer, &version_at(version))?;

        let mut expected = feature_messages().to_vec();
        expected.extend(
            negotiated_features(&peer, version)
                .into_iter()
                .map(Message::Feature),
        );
        expected.push(Message::Verack);
        assert_eq!(responses, expected);
        let announced = responses
            .iter()
            .any(|response| matches!(response, Message::Feature(_)));
        assert_eq!(announced, version >= FEATURE_VERSION);
    }
    Ok(())
}

#[test]
fn remote_feature_is_accepted_before_verack_and_rejected_after() -> Result<(), PeerError> {
    let feature = Message::Feature(FeatureAnnouncement::new(
        FeatureId::from_raw_unchecked(b"BIP332".to_vec()),
        vec![1],
    ));
    let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
    dispatch_inbound(&mut peer, &version_at(PROTOCOL_VERSION))?;

    assert_eq!(dispatch_inbound(&mut peer, &feature)?, []);
    assert_eq!(peer.remote_feature(b"BIP332"), Some([1].as_slice()));

    dispatch_inbound(&mut peer, &Message::Verack)?;
    assert_eq!(peer.state, PeerState::Ready);
    let before = peer_snapshot(&peer);
    assert!(matches!(
        dispatch_inbound(&mut peer, &feature),
        Err(PeerError::Misbehavior(_))
    ));
    assert_eq!(peer_snapshot(&peer), before);
    assert_eq!(peer.remote_feature(b"BIP332"), Some([1].as_slice()));
    Ok(())
}

#[test]
fn version_reply_sends_the_offered_sendpackages_once_before_verack() -> Result<(), PeerError> {
    let both = PKG_RELAY_PKGTXNS | PKG_RELAY_ANC;
    let mut peer = Peer::new(Cursor::new(Vec::<u8>::new()), Magic::BITCOIN);
    peer.offer_package_relay(both | (1 << 40));
    peer.offer_stale_tip_relay(true);

    let first = dispatch_inbound(&mut peer, &version_at(PROTOCOL_VERSION))?;

    let mut expected = feature_messages().to_vec();
    expected.extend(
        negotiated_features(&peer, PROTOCOL_VERSION)
            .into_iter()
            .map(Message::Feature),
    );
    expected.push(Message::SendPackages(SendPackages { versions: both }));
    expected.push(Message::Verack);
    assert_eq!(first, expected);

    let before = peer_snapshot(&peer);
    let remote_version = peer.remote_version.clone();
    assert!(matches!(
        dispatch_inbound(&mut peer, &version_at(PROTOCOL_VERSION - 1)),
        Err(PeerError::Misbehavior("duplicate version message"))
    ));
    assert_eq!(peer_snapshot(&peer), before);
    assert_eq!(peer.remote_version, remote_version);
    Ok(())
}

const BOTH_PACKAGE_BITS: u64 = PKG_RELAY_PKGTXNS | PKG_RELAY_ANC;

fn package_peer(bits: u64) -> Result<Peer<Cursor<Vec<u8>>>, PeerError> {
    let mut peer = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
    peer.offer_package_relay(bits);
    dispatch_inbound(&mut peer, &version_at(PROTOCOL_VERSION))?;
    dispatch_inbound(&mut peer, &Message::WtxidRelay)?;
    dispatch_inbound(
        &mut peer,
        &Message::SendPackages(SendPackages { versions: bits }),
    )?;
    dispatch_inbound(&mut peer, &Message::Verack)?;
    assert_eq!(peer.package_relay_versions(), bits);
    Ok(peer)
}

fn package_item(inv_type: u32, wtxid: Wtxid) -> Inventory {
    Inventory::Unknown {
        inv_type,
        hash: *wtxid.as_bytes(),
    }
}

fn dispatch_over<S>(
    peer: &mut Peer<S>,
    message: &Message,
    inventory: &dyn TxInventory,
) -> Result<Vec<Message>, PeerError> {
    let collected = RefCell::new(Vec::new());
    dispatch_inbound_full(
        peer,
        message,
        None,
        Some(inventory),
        &|| true,
        &|| true,
        &mut |response| {
            collected.borrow_mut().push(response);
            Ok(())
        },
        &mut |_| {},
        &mut |_| {},
    )?;
    Ok(collected.into_inner())
}

#[test]
fn package_messages_without_negotiation_are_protocol_violations() {
    let wtxid = dummy_tx(1).wtxid();
    for message in [
        Message::AncPkgInfo(AncPkgInfo {
            wtxids: vec![wtxid],
        }),
        Message::GetPkgTxns(GetPkgTxns {
            wtxids: vec![wtxid],
        }),
        Message::PkgTxnsPayload(bytes::Bytes::new()),
        Message::GetData(vec![package_item(MSG_ANCPKGINFO, wtxid)]),
        Message::GetData(vec![package_item(MSG_PKGTXNS, wtxid)]),
        Message::Inv(vec![package_item(MSG_ANCPKGINFO, wtxid)]),
        Message::Inv(vec![package_item(MSG_PKGTXNS, wtxid)]),
    ] {
        let mut peer = ready_peer();
        let before = peer_snapshot(&peer);

        assert!(
            matches!(
                dispatch_inbound(&mut peer, &message),
                Err(PeerError::Misbehavior(_))
            ),
            "{message:?}"
        );
        assert_eq!(peer_snapshot(&peer), before);
        assert!(peer.take_package_request().is_none());
    }
}

#[test]
fn a_negotiated_bit_admits_only_its_own_messages() -> Result<(), PeerError> {
    let wtxid = dummy_tx(1).wtxid();
    let ancestor_only = [
        Message::GetPkgTxns(GetPkgTxns {
            wtxids: vec![wtxid],
        }),
        Message::PkgTxnsPayload(bytes::Bytes::new()),
    ];
    for message in ancestor_only {
        let mut peer = package_peer(PKG_RELAY_ANC)?;
        assert!(matches!(
            dispatch_inbound(&mut peer, &message),
            Err(PeerError::Misbehavior(_))
        ));
    }
    let batch_only = [
        Message::AncPkgInfo(AncPkgInfo {
            wtxids: vec![wtxid],
        }),
        Message::GetData(vec![package_item(MSG_ANCPKGINFO, wtxid)]),
    ];
    for message in batch_only {
        let mut peer = package_peer(PKG_RELAY_PKGTXNS)?;
        assert!(matches!(
            dispatch_inbound(&mut peer, &message),
            Err(PeerError::Misbehavior(_))
        ));
    }
    let mut peer = package_peer(PKG_RELAY_PKGTXNS)?;
    assert_eq!(
        dispatch_inbound(&mut peer, &Message::PkgTxnsPayload(bytes::Bytes::new()))?,
        []
    );
    Ok(())
}

#[test]
fn package_only_inventory_types_are_never_valid_in_inv_or_getdata6() -> Result<(), PeerError> {
    let wtxid = dummy_tx(1).wtxid();
    for message in [
        Message::Inv(vec![package_item(MSG_ANCPKGINFO, wtxid)]),
        Message::Inv(vec![package_item(MSG_PKGTXNS, wtxid)]),
        Message::GetData(vec![package_item(MSG_PKGTXNS, wtxid)]),
    ] {
        let mut peer = package_peer(BOTH_PACKAGE_BITS)?;
        assert!(
            matches!(
                dispatch_inbound(&mut peer, &message),
                Err(PeerError::Misbehavior(_))
            ),
            "{message:?}"
        );
    }
    Ok(())
}

#[test]
fn getdata_ancpkginfo_serves_the_resident_package_and_reports_the_rest() -> Result<(), PeerError> {
    let parent = dummy_tx(1);
    let child = dummy_tx(2);
    let orphan = dummy_tx(3);
    let unknown = dummy_tx(4).wtxid();
    let misdirected = dummy_tx(5);
    let inventory = FakeTxInventory::empty()
        .with_resident_tx(parent.clone())
        .with_resident_tx(child.clone())
        .with_resident_tx(misdirected.clone())
        .with_tx(orphan.clone())
        .with_ancestor_package(child.wtxid(), vec![parent.wtxid(), child.wtxid()])
        .with_ancestor_package(
            misdirected.wtxid(),
            vec![misdirected.wtxid(), parent.wtxid()],
        );
    let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

    let responses = dispatch_over(
        &mut peer,
        &Message::GetData(vec![
            package_item(MSG_ANCPKGINFO, child.wtxid()),
            package_item(MSG_ANCPKGINFO, orphan.wtxid()),
            package_item(MSG_ANCPKGINFO, unknown),
            package_item(MSG_ANCPKGINFO, misdirected.wtxid()),
        ]),
        &inventory,
    )?;

    assert_eq!(
        responses,
        vec![
            Message::AncPkgInfo(AncPkgInfo {
                wtxids: vec![parent.wtxid(), child.wtxid()],
            }),
            Message::NotFound(vec![
                package_item(MSG_ANCPKGINFO, orphan.wtxid()),
                package_item(MSG_ANCPKGINFO, unknown),
                package_item(MSG_ANCPKGINFO, misdirected.wtxid()),
            ]),
        ]
    );
    Ok(())
}

#[test]
fn getdata_ancpkginfo_without_an_inventory_is_reported_missing() -> Result<(), PeerError> {
    let subject = dummy_tx(1).wtxid();
    let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

    let responses = dispatch_inbound(
        &mut peer,
        &Message::GetData(vec![package_item(MSG_ANCPKGINFO, subject)]),
    )?;

    assert_eq!(
        responses,
        vec![Message::NotFound(vec![package_item(
            MSG_ANCPKGINFO,
            subject
        )])]
    );
    Ok(())
}

#[test]
fn getpkgtxns_is_all_resident_in_request_order_or_one_notfound() -> Result<(), PeerError> {
    let parent = dummy_tx(1);
    let child = dummy_tx(2);
    let orphan = dummy_tx(3);
    let unknown = dummy_tx(4).wtxid();
    let inventory = FakeTxInventory::empty()
        .with_resident_tx(parent.clone())
        .with_resident_tx(child.clone())
        .with_tx(orphan.clone());
    let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

    let served = dispatch_over(
        &mut peer,
        &Message::GetPkgTxns(GetPkgTxns {
            wtxids: vec![child.wtxid(), parent.wtxid(), child.wtxid()],
        }),
        &inventory,
    )?;
    assert_eq!(
        served,
        vec![Message::PkgTxns(PkgTxns {
            txs: vec![child.clone(), parent.clone(), child.clone()],
        })]
    );

    for unavailable in [orphan.wtxid(), unknown] {
        let wtxids = vec![parent.wtxid(), unavailable, child.wtxid()];
        let responses = dispatch_over(
            &mut peer,
            &Message::GetPkgTxns(GetPkgTxns {
                wtxids: wtxids.clone(),
            }),
            &inventory,
        )?;
        assert_eq!(
            responses,
            vec![Message::NotFound(vec![Inventory::Unknown {
                inv_type: MSG_PKGTXNS,
                hash: combined_package_hash(&wtxids),
            }])]
        );
    }
    Ok(())
}

#[test]
fn getpkgtxns_without_an_inventory_is_one_notfound() -> Result<(), PeerError> {
    let wtxids = vec![dummy_tx(1).wtxid(), dummy_tx(2).wtxid()];
    let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

    let responses = dispatch_inbound(
        &mut peer,
        &Message::GetPkgTxns(GetPkgTxns {
            wtxids: wtxids.clone(),
        }),
    )?;

    assert_eq!(
        responses,
        vec![Message::NotFound(vec![Inventory::Unknown {
            inv_type: MSG_PKGTXNS,
            hash: combined_package_hash(&wtxids),
        }])]
    );
    Ok(())
}

#[test]
fn getpkgtxns_that_cannot_fit_one_frame_is_unavailable() -> Result<(), PeerError> {
    let bulky: Vec<Tx> = (1..=3_u8)
        .map(|byte| {
            let mut tx = dummy_tx(byte);
            tx.inputs[0].script_sig = vec![byte; 1_500_000].into();
            tx
        })
        .collect();
    let wtxids: Vec<Wtxid> = bulky.iter().map(Tx::wtxid).collect();
    let inventory = bulky
        .into_iter()
        .fold(FakeTxInventory::empty(), FakeTxInventory::with_resident_tx);
    let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

    let responses = dispatch_over(
        &mut peer,
        &Message::GetPkgTxns(GetPkgTxns {
            wtxids: wtxids.clone(),
        }),
        &inventory,
    )?;

    assert_eq!(
        responses,
        vec![Message::NotFound(vec![Inventory::Unknown {
            inv_type: MSG_PKGTXNS,
            hash: combined_package_hash(&wtxids),
        }])]
    );
    Ok(())
}

#[test]
fn getpkgtxns_is_left_unanswered_while_the_production_gate_is_closed() -> Result<(), PeerError> {
    let tx = dummy_tx(1);
    let inventory = FakeTxInventory::empty().with_resident_tx(tx.clone());
    let mut peer = package_peer(BOTH_PACKAGE_BITS)?;
    let loaded = AtomicUsize::new(0);
    let counting = CountingResident {
        inner: &inventory,
        loaded: &loaded,
    };

    dispatch_inbound_full(
        &mut peer,
        &Message::GetPkgTxns(GetPkgTxns {
            wtxids: vec![tx.wtxid()],
        }),
        None,
        Some(&counting),
        &|| true,
        &|| false,
        &mut |response| panic!("a closed gate queued {response:?}"),
        &mut |_| {},
        &mut |_| {},
    )?;

    assert_eq!(loaded.load(Ordering::SeqCst), 0, "no body was loaded");
    Ok(())
}

struct CountingResident<'a> {
    inner: &'a FakeTxInventory,
    loaded: &'a AtomicUsize,
}

impl TxInventory for CountingResident<'_> {
    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool {
        self.inner.have_tx(hash, hash_is_wtxid)
    }

    fn get_tx(&self, txid: Txid) -> Option<Tx> {
        self.inner.get_tx(txid)
    }

    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        self.inner.get_tx_by_wtxid(wtxid)
    }

    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>> {
        self.inner.resident_ancestor_package(wtxid)
    }

    fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
        self.loaded.fetch_add(1, Ordering::SeqCst);
        self.inner.resident_package(wtxids)
    }
}

#[test]
fn ancpkginfo_hands_the_missing_members_to_the_request_owner_once() -> Result<(), PeerError> {
    let parent = dummy_tx(1);
    let child = dummy_tx(2);
    let message = Message::AncPkgInfo(AncPkgInfo {
        wtxids: vec![parent.wtxid(), child.wtxid()],
    });
    let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

    let refused = FakeTxInventory::empty()
        .with_tx(child.clone())
        .with_have(*parent.wtxid().as_bytes())
        .with_have(*child.wtxid().as_bytes());
    assert_eq!(dispatch_over(&mut peer, &message, &refused)?, []);
    assert_eq!(
        peer.take_package_request(),
        Some(PackageRequest {
            subject: child.wtxid(),
            wtxids: vec![parent.wtxid(), child.wtxid()],
        })
    );
    assert_eq!(peer.take_package_request(), None, "one handoff per message");

    let resident_parent = FakeTxInventory::empty().with_resident_tx(parent);
    dispatch_over(&mut peer, &message, &resident_parent)?;
    assert_eq!(
        peer.take_package_request(),
        Some(PackageRequest {
            subject: child.wtxid(),
            wtxids: vec![child.wtxid()],
        })
    );
    Ok(())
}

#[test]
fn ancpkginfo_requests_nothing_when_nothing_is_missing_or_the_package_is_too_large()
-> Result<(), PeerError> {
    let max = bitcoin_rs_mempool::standardness::MAX_PACKAGE_COUNT;
    let held: Vec<Tx> = (1..=3_u8).map(dummy_tx).collect();
    let everything = held
        .iter()
        .cloned()
        .fold(FakeTxInventory::empty(), FakeTxInventory::with_resident_tx);
    let mut peer = package_peer(BOTH_PACKAGE_BITS)?;
    dispatch_over(
        &mut peer,
        &Message::AncPkgInfo(AncPkgInfo {
            wtxids: held.iter().map(Tx::wtxid).collect(),
        }),
        &everything,
    )?;
    assert_eq!(
        peer.take_package_request(),
        None,
        "subject already resident"
    );

    let too_many: Vec<Wtxid> = (0..=max)
        .map(|index| {
            let byte = u8::try_from(index).unwrap_or(u8::MAX);
            Wtxid::from(Hash256::from_le_bytes(&[byte.wrapping_add(1); 32]))
        })
        .collect();
    assert_eq!(too_many.len(), max + 1);
    dispatch_over(
        &mut peer,
        &Message::AncPkgInfo(AncPkgInfo { wtxids: too_many }),
        &FakeTxInventory::empty(),
    )?;
    assert_eq!(peer.take_package_request(), None, "above admission bound");

    let exact: Vec<Wtxid> = (1..=u8::try_from(max).unwrap_or(u8::MAX))
        .map(|byte| Wtxid::from(Hash256::from_le_bytes(&[byte; 32])))
        .collect();
    dispatch_over(
        &mut peer,
        &Message::AncPkgInfo(AncPkgInfo {
            wtxids: exact.clone(),
        }),
        &FakeTxInventory::empty(),
    )?;
    assert_eq!(
        peer.take_package_request().map(|request| request.wtxids),
        Some(exact),
        "a package at the bound is requested whole"
    );
    Ok(())
}

#[test]
fn ancpkginfo_is_not_requested_while_transaction_relay_is_closed() -> Result<(), PeerError> {
    let wtxid = dummy_tx(1).wtxid();
    let mut peer = package_peer(BOTH_PACKAGE_BITS)?;

    let responses = dispatch_collect_gated(
        &mut peer,
        &Message::AncPkgInfo(AncPkgInfo {
            wtxids: vec![wtxid],
        }),
        None,
        None,
        false,
    );

    assert_eq!(responses, []);
    assert_eq!(peer.take_package_request(), None);
    Ok(())
}

fn test_header(prev_blockhash: BlockHash, nonce: u32) -> Header {
    Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&[0; 32]),
        time: nonce,
        bits: CompactTarget::from_consensus(bitcoin_rs_chain::regtest_fixture::REGTEST_BITS),
        nonce,
    }
}
