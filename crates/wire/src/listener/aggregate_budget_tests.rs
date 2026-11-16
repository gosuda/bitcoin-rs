use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::bip152::{BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_compact_blocks::{CmpctBlock, GetBlockTxn};
use bitcoin_rs_consensus::primitives::Header;

use super::getdata_pause_tests::{
    FAILSAFE, MAGIC, ScriptedChain, Served, TestResult, WriterKind, block, inventory_of,
    parked_peer, read_messages, scripted, shared_with, wait_until, wire_len_of,
};
use super::{
    DeferredStep, Keepalive, KeepaliveAction, ParkedStep, ProductionSink, TIMEOUT_INTERVAL,
    notfound_wire_bound, reply_bound, retry_deferred_request, step_parked_getdata,
};
use crate::connection::{OutboundBudget, Refusal, SharedOutboundBudget};
use crate::test_support::hog;
use crate::{Message, PeerLease};

#[test]
fn compact_completion_reserves_before_consuming_pending_and_transfers_image_credit() -> TestResult {
    struct EmptyHints;
    impl crate::compact_blocks::CompactBlockHints for EmptyHints {
        fn for_each_identity(
            &self,
            _: &mut dyn FnMut(
                bitcoin_rs_consensus::primitives::Txid,
                bitcoin_rs_consensus::primitives::Wtxid,
            ),
        ) {
        }
        fn get_tx_by_txid(
            &self,
            _: bitcoin_rs_consensus::primitives::Txid,
        ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
            None
        }
        fn get_tx_by_wtxid(
            &self,
            _: bitcoin_rs_consensus::primitives::Wtxid,
        ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
            None
        }
    }
    for scenario in ["complete", "cancelled", "full"] {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut compact = HeaderAndShortIds::from_block(&block, 7, 2, &[])
            .map_err(|_| "genesis compact block")?;
        let keys = ShortId::calculate_siphash_keys(&block.header, 7);
        compact.prefilled_txs.clear();
        compact.short_ids = vec![ShortId::with_siphash_keys(
            block.txdata[0].compute_wtxid().as_byte_array(),
            keys,
        )];
        let mut reconstruction = crate::compact_blocks::Reconstruction::new();
        assert!(matches!(
            reconstruction.receive_cmpctblock(
                &CmpctBlock {
                    compact_block: compact
                },
                2,
                &EmptyHints,
                Instant::now(),
            ),
            crate::compact_blocks::Outcome::RequestMissing(_)
        ));
        let message = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
            transactions: bitcoin::bip152::BlockTransactions {
                block_hash: block.block_hash(),
                transactions: block.txdata.clone(),
            },
        });
        let (queue, _receiver) = crate::test_support::message_channel();
        let lease = PeerLease::new(queue);
        let sink = ProductionSink::new(&lease, None);
        let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
        let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(1);
        shared.blocks_tx = blocks_tx;
        let ledger = Arc::clone(shared.block_memory.ledger());
        let capacity = ledger.capacity();
        let held = if scenario == "full" {
            Some(shared.block_memory.reserve(capacity, || false)?)
        } else {
            None
        };
        if scenario == "cancelled" {
            lease.cancel();
        }
        super::process_compact_wire_message(
            &message,
            &mut reconstruction,
            Some(2),
            None,
            &sink,
            bitcoin_rs_consensus::primitives::PeerEndpoint::from(([127, 0, 0, 1], 8333)),
            &shared,
        );
        if scenario != "complete" {
            assert_eq!(reconstruction.pending_len(), 1);
            assert!(blocks_rx.is_empty());
        } else {
            assert_eq!(reconstruction.pending_len(), 0);
            let inbound = blocks_rx
                .recv_timeout(FAILSAFE)
                .map_err(|_| "reconstructed block was not delivered")?;
            assert!(!ledger.try_take(capacity));
            drop(inbound);
        }
        drop(reconstruction);
        drop(held);
        assert!(ledger.try_take(capacity));
        ledger.give_back(capacity);
    }
    Ok(())
}

#[test]
fn headroom_retains_one_credit() -> TestResult {
    let reserve = 1_000;
    let aggregate = Arc::new(SharedOutboundBudget::with_limits(reserve + 64, 64));
    let (queue, receiver) = crate::test_support::message_channel();
    let lease = PeerLease::new_with_budget(
        queue,
        true,
        OutboundBudget::with_block_reserve(100, 1 << 20, reserve),
    )
    .with_shared_budget(&aggregate);
    let sink = ProductionSink::new(&lease, None);

    assert!(sink.headroom());
    assert!(
        sink.headroom(),
        "a second reservation would not fit; the held credit is reused"
    );
    assert!(sink.headroom());
    assert_eq!(
        aggregate.pending(),
        reserve,
        "repeated headroom charges the aggregate once"
    );
    assert!(
        matches!(lease.try_reserve_production(), Err(Refusal::Shared)),
        "the one credit the bulk limit allows is the sink's"
    );
    assert_eq!(sink.refusal(), None, "nothing was refused to the sink");

    sink.send(Message::Pong(1))
        .map_err(|_| "a send under the held reservation")?;
    assert_eq!(
        aggregate.pending(),
        wire_len_of(&Message::Pong(1))?,
        "the spent credit shrank to the frame it carries"
    );
    assert!(
        !sink.headroom(),
        "with the frame still queued, a new reservation no longer fits"
    );
    assert_eq!(sink.refusal(), Some(Refusal::Shared));

    assert_eq!(receiver.try_recv(), Ok(Message::Pong(1)));
    assert_eq!(
        aggregate.pending(),
        0,
        "the writer's drop returns the frame"
    );
    assert!(sink.headroom(), "room is reserved again once it returns");
    Ok(())
}

#[test]
fn parked_misses_reserved_before_build() -> TestResult {
    let miss = Inventory::Transaction(bitcoin::Txid::from_byte_array([3; 32]));
    let bound = notfound_wire_bound(1);
    let aggregate = Arc::new(SharedOutboundBudget::with_limits(10 * bound, 0));
    let hogged = 10 * bound - (bound - 1);
    let hold = hog(&aggregate, hogged);
    let (queue, receiver) = crate::test_support::message_channel();
    let lease = PeerLease::new(queue).with_shared_budget(&aggregate);
    let shared = shared_with(ScriptedChain { blocks: Vec::new() });
    let mut peer = parked_peer(Vec::new());
    peer.pending_notfound = vec![miss];
    let mut keepalive = Keepalive::starting(Instant::now());
    let mut parked_since = None;

    let step = step_parked_getdata(
        &mut peer,
        &shared,
        &lease,
        &mut keepalive,
        &mut parked_since,
    )?;

    assert_eq!(step, ParkedStep::StillParked);
    assert_eq!(
        peer.pending_notfound,
        vec![miss],
        "a refused reservation takes nothing out of the list"
    );
    assert!(receiver.is_empty());
    assert_eq!(aggregate.pending(), hogged, "a refusal charges nothing");
    assert!(
        keepalive.shared_refused,
        "the aggregate's refusal is a stall, not an error"
    );
    assert!(!lease.is_cancelled());

    drop(hold);
    step_parked_getdata(
        &mut peer,
        &shared,
        &lease,
        &mut keepalive,
        &mut parked_since,
    )?;

    assert_eq!(peer.pending_notfound, Vec::new());
    assert_eq!(receiver.try_recv(), Ok(Message::NotFound(vec![miss])));
    assert_eq!(aggregate.pending(), 0);
    Ok(())
}

#[test]
fn reply_bound_covers_actual_replies() -> TestResult {
    assert_eq!(
        reply_bound(&Message::Ping(1), false),
        Some(wire_len_of(&Message::Pong(u64::MAX))?)
    );

    let get_headers = Message::GetHeaders(GetHeadersMessage::new(
        Vec::new(),
        bitcoin::BlockHash::all_zeros(),
    ));
    let full_headers = Message::Headers(vec![
        Header::default();
        crate::wire::MAX_HEADERS_MESSAGE_COUNT
    ]);
    assert_eq!(
        reply_bound(&get_headers, false),
        Some(wire_len_of(&full_headers)?)
    );

    assert_eq!(reply_bound(&Message::GetAddr, false), None);
    let socket = bitcoin_rs_consensus::primitives::PeerEndpoint::from(([1, 2, 3, 4], 8333));
    let addr_v1 = Message::Addr(vec![
        (
            0,
            Address::new(
                &socket
                    .socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
                ServiceFlags::NONE
            )
        );
        crate::wire::MAX_ADDR_MESSAGE_COUNT
    ]);
    let addr_v2 = Message::AddrV2(vec![
        AddrV2Message {
            time: 0,
            services: ServiceFlags::from(u64::MAX),
            addr: AddrV2::Ipv6(std::net::Ipv6Addr::LOCALHOST),
            port: 8333,
        };
        crate::wire::MAX_ADDR_MESSAGE_COUNT
    ]);
    let addr_bound = reply_bound(&Message::GetAddr, true).ok_or("an answerable getaddr")?;
    assert!(addr_bound >= wire_len_of(&addr_v1)?);
    assert!(addr_bound >= wire_len_of(&addr_v2)?);
    Ok(())
}

#[test]
fn reply_bound_covers_compact_follow_ups() -> TestResult {
    let slots = 3_000_u64;
    let keys = (1, 2);
    let short_ids = (0..slots)
        .map(|slot| ShortId::with_siphash_keys(&[slot.to_le_bytes()[0]; 32], keys))
        .collect();
    let header: bitcoin::block::Header = bitcoin::consensus::deserialize(&[0_u8; 80])?;
    let cmpct = Message::CmpctBlock(CmpctBlock {
        compact_block: HeaderAndShortIds {
            header,
            nonce: 0,
            short_ids,
            prefilled_txs: Vec::new(),
        },
    });
    let block_hash = bitcoin::BlockHash::all_zeros();
    let worst_getblocktxn = Message::GetBlockTxn(GetBlockTxn {
        txs_request: BlockTransactionsRequest {
            block_hash,
            indexes: (0..slots).map(|slot| slot * 70_000).collect(),
        },
    });
    let fallback = Message::GetData(vec![Inventory::WitnessBlock(block_hash)]);
    let cmpct_bound = reply_bound(&cmpct, false).ok_or("a reserved cmpctblock")?;
    assert!(cmpct_bound >= wire_len_of(&worst_getblocktxn)?);
    assert!(cmpct_bound >= wire_len_of(&fallback)?);

    let blocktxn = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
        transactions: bitcoin::bip152::BlockTransactions {
            block_hash,
            transactions: Vec::new(),
        },
    });
    let blocktxn_bound = reply_bound(&blocktxn, false).ok_or("a reserved blocktxn")?;
    assert!(blocktxn_bound >= wire_len_of(&fallback)?);
    Ok(())
}

#[test]
fn notfound_wire_bound_is_exact() -> TestResult {
    for items in [1, 2, 252, 253, 1_000] {
        let miss = Inventory::Transaction(bitcoin::Txid::from_byte_array([9; 32]));
        assert_eq!(
            notfound_wire_bound(items),
            wire_len_of(&Message::NotFound(vec![miss; items]))?,
            "{items} items"
        );
    }
    Ok(())
}

#[test]
fn stall_exclusion_removes_only_shared_refusals() {
    let t0 = Instant::now();
    let since = t0 + Duration::from_secs(10);
    let long_after = t0 + TIMEOUT_INTERVAL + Duration::from_secs(100);

    let mut shared = Keepalive::starting(t0);
    let mut parked = Some(since);
    shared.note_refusal(Refusal::Shared);
    shared.settle_pass(since, &mut parked);
    assert_eq!(
        shared.stall,
        Some(since),
        "an aggregate refusal opens a stall"
    );
    assert_ne!(
        shared.next_action(long_after),
        KeepaliveAction::Expired,
        "the open stall is not silence in either direction"
    );
    assert_ne!(
        shared.next_action_while_parked(long_after),
        KeepaliveAction::Expired
    );

    shared.note_refusal(Refusal::Shared);
    shared.settle_pass(long_after, &mut parked);
    assert_eq!(
        shared.stall,
        Some(since),
        "a continued refusal keeps one stall"
    );

    shared.settle_pass(long_after, &mut parked);
    assert_eq!(shared.stall, None, "a pass without a refusal closes it");
    assert_eq!(
        parked,
        Some(long_after),
        "the parked marker moves past the stalled time"
    );
    assert_ne!(
        shared.next_action(long_after),
        KeepaliveAction::Expired,
        "the closed stall stays excluded from both directions"
    );
    assert_eq!(
        shared.next_action(long_after + TIMEOUT_INTERVAL + Duration::from_secs(1)),
        KeepaliveAction::Expired,
        "silence after the stall is counted"
    );

    let mut local = Keepalive::starting(t0);
    let mut none = None;
    local.note_refusal(Refusal::Local);
    local.settle_pass(since, &mut none);
    assert_eq!(local.stall, None, "the connection's own queue is no stall");
    assert_eq!(local.next_action(long_after), KeepaliveAction::Expired);
}

struct DeferredHarness {
    lease: PeerLease,
    peer: crate::Peer<std::io::Cursor<Vec<u8>>>,
    keepalive: Keepalive,
    parked_since: Option<Instant>,
}

impl DeferredHarness {
    fn retry(&mut self, message: Option<Message>, now: Instant) -> DeferredStep {
        self.peer.deferred_inbound = message;
        retry_deferred_request(
            &mut self.peer,
            &self.lease,
            &mut self.keepalive,
            &mut self.parked_since,
            false,
            now,
        )
    }

    fn retry_held(&mut self, now: Instant) -> DeferredStep {
        retry_deferred_request(
            &mut self.peer,
            &self.lease,
            &mut self.keepalive,
            &mut self.parked_since,
            false,
            now,
        )
    }
}

#[test]
fn deferred_request_retries_and_keeps_the_existing_local_rules() -> TestResult {
    let bound = reply_bound(&Message::Ping(1), false).ok_or("a reserved ping")?;
    let aggregate = Arc::new(SharedOutboundBudget::with_limits(4 * bound, 0));
    let hold = hog(&aggregate, 3 * bound + 1);
    let (queue, _receiver) = crate::test_support::message_channel();
    let t0 = Instant::now();
    let mut harness = DeferredHarness {
        lease: PeerLease::new(queue).with_shared_budget(&aggregate),
        peer: parked_peer(Vec::new()),
        keepalive: Keepalive::starting(t0),
        parked_since: None,
    };

    assert!(matches!(harness.retry(None, t0), DeferredStep::NoneHeld));

    assert!(matches!(
        harness.retry(Some(Message::Ping(7)), t0),
        DeferredStep::Waiting
    ));
    assert_eq!(harness.peer.deferred_inbound, Some(Message::Ping(7)));
    assert!(
        harness.keepalive.shared_refused,
        "the refusal is reported as a stall"
    );
    assert!(harness.parked_since.is_some());
    assert!(!harness.lease.is_cancelled());

    drop(hold);
    let DeferredStep::Ready(message, Some(credit)) = harness.retry_held(t0) else {
        return Err("the reply is reserved once the aggregate has room".into());
    };
    assert_eq!(message, Message::Ping(7));
    assert_eq!(credit.bytes(), bound);
    assert_eq!(harness.parked_since, None);
    assert_eq!(harness.peer.deferred_inbound, None);
    drop(credit);

    let (queue, _receiver) = crate::test_support::message_channel();
    harness.lease = PeerLease::new_with_budget(
        queue,
        true,
        OutboundBudget::with_block_reserve(1, 1 << 20, 1),
    );
    harness
        .lease
        .send(Message::Ping(1))
        .map_err(|_| "a fresh queue admits one message")?;
    assert!(matches!(
        harness.retry(Some(Message::Ping(8)), t0),
        DeferredStep::Ended
    ));
    assert!(harness.lease.is_cancelled());

    let (queue, _receiver) = crate::test_support::message_channel();
    harness.lease = PeerLease::new(queue);
    harness.lease.budget_handle().mark_writer_dead();
    assert!(matches!(
        harness.retry(Some(Message::Ping(9)), t0),
        DeferredStep::Ended
    ));

    let later = t0 + TIMEOUT_INTERVAL + Duration::from_secs(5);
    let hold = hog(&aggregate, 3 * bound + 1);
    let (queue, _receiver) = crate::test_support::message_channel();
    harness.lease = PeerLease::new(queue).with_shared_budget(&aggregate);
    harness.keepalive = Keepalive::starting(t0);
    harness.parked_since = Some(t0);
    assert!(matches!(
        harness.retry(Some(Message::Ping(10)), later),
        DeferredStep::Ended
    ));
    harness.keepalive = Keepalive::starting(t0);
    harness.keepalive.stall = Some(t0);
    harness.parked_since = Some(t0);
    assert!(matches!(
        harness.retry(Some(Message::Ping(11)), later),
        DeferredStep::Waiting
    ));
    drop(hold);
    Ok(())
}

fn answered_once_after_the_aggregate_drains(request: &Message, expected: Message) -> TestResult {
    let bound = reply_bound(request, true).ok_or("a request-scoped reply")?;
    let aggregate = Arc::new(SharedOutboundBudget::with_limits(4 * bound, 0));
    let hold = hog(&aggregate, 3 * bound + 1);
    let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
    shared.address_book = Some(crate::addrman::AddressBook::open(
        None,
        MAGIC.to_bytes(),
        true,
        None,
    ));
    let mut served = Served::start_on(
        shared,
        OutboundBudget::with_block_reserve(100, 1 << 20, 1),
        Some(&aggregate),
        &WriterKind::Gated,
    )?;

    served.client.send(request)?;
    std::thread::sleep(Duration::from_millis(300));
    let ping_len = wire_len_of(&Message::Ping(0))?;
    assert!(
        served.budget.pending() == (0, 0) && served.budget.control_pending() <= (1, ping_len),
        "{request:?}: no reply is reserved or queued while the aggregate is full \
         (only the originated control probe may sit, on its bounded lane): {:?}",
        served.budget.pending()
    );
    assert!(
        !served.lease.is_cancelled(),
        "{request:?}: the aggregate never ends a session"
    );

    drop(hold);
    served.open_gate();
    // The message loop's first-pass keepalive probe met the same full
    // aggregate as the deferred reply: whether it was refused or queued
    // under the remaining room depends on the request's reply bound (the
    // relaxed pending check above accepts either). With room again it
    // drains first (top-of-pass), then the deferred reply follows.
    assert!(
        matches!(
            read_messages(&mut served.client, 1)?.as_slice(),
            [Message::Ping(_)]
        ),
        "{request:?}: the originated keepalive probe drains with the aggregate"
    );
    assert_eq!(
        read_messages(&mut served.client, 1)?,
        vec![expected],
        "{request:?}: the deferred request was answered exactly once"
    );
    served.client.send(&Message::Ping(99))?;
    assert_eq!(
        read_messages(&mut served.client, 1)?,
        vec![Message::Pong(99)],
        "{request:?}: the session serves fresh traffic after the drain"
    );

    served.lease.cancel();
    let outcome = served.session_outcome(FAILSAFE)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

#[test]
fn request_deferred_not_reply() -> TestResult {
    answered_once_after_the_aggregate_drains(&Message::Ping(7), Message::Pong(7))?;
    answered_once_after_the_aggregate_drains(
        &Message::GetHeaders(GetHeadersMessage::new(
            Vec::new(),
            bitcoin::BlockHash::all_zeros(),
        )),
        Message::Headers(Vec::new()),
    )?;
    answered_once_after_the_aggregate_drains(&Message::GetAddr, Message::Addr(Vec::new()))
}

#[test]
fn a_bulk_tail_parked_on_the_aggregate_leaves_the_margin_for_control() -> TestResult {
    let block_a = block(11);
    let entry = scripted(&block_a);
    let block_len = wire_len_of(&Message::BlockBytes(entry.1.clone()))?;
    let aggregate = Arc::new(SharedOutboundBudget::with_limits(10 * block_len, block_len));
    let hold = hog(&aggregate, 8 * block_len + 1);
    let mut served = Served::start_on(
        shared_with(ScriptedChain {
            blocks: vec![entry],
        }),
        OutboundBudget::with_block_reserve(100, 1 << 20, block_len),
        Some(&aggregate),
        &WriterKind::Gated,
    )?;

    served
        .client
        .send(&Message::GetData(vec![inventory_of(&block_a)]))?;
    std::thread::sleep(Duration::from_millis(300));
    let ping_len = wire_len_of(&Message::Ping(3))?;
    wait_until("the originated keepalive probe to be queued", || {
        served.budget.control_pending() == (1, ping_len)
    })?;
    served
        .lease
        .send(Message::Ping(3))
        .map_err(|_| "the margin keeps control traffic flowing")?;
    assert_eq!(served.budget.pending(), (1, ping_len));
    assert_eq!(served.budget.control_pending(), (1, ping_len));
    assert_eq!(aggregate.pending(), 8 * block_len + 1 + 2 * ping_len);
    assert!(
        !served.lease.is_cancelled(),
        "a parked bulk tail never cancels the lease"
    );

    served.open_gate();
    assert!(
        matches!(
            read_messages(&mut served.client, 2)?.as_slice(),
            [Message::Ping(_), Message::Ping(3)],
        ),
        "the originated probe and the queued control ping drain in order"
    );
    drop(hold);
    assert_eq!(
        read_messages(&mut served.client, 1)?,
        vec![Message::Block(
            bitcoin_rs_consensus::primitives::BlockImage::from_local(block_a),
        )],
        "the tail is served once the aggregate has room"
    );

    served.lease.cancel();
    let outcome = served.session_outcome(FAILSAFE)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

#[test]
fn conditional_compact_defers_on_locally_full_queue() -> TestResult {
    let mut served = Served::start(
        shared_with(ScriptedChain { blocks: Vec::new() }),
        OutboundBudget::with_block_reserve(1, 1 << 20, 1),
        &WriterKind::Gated,
    )?;
    let ping_len = wire_len_of(&Message::Ping(1))?;
    // The message loop's first-pass keepalive probe rides the bounded
    // control lane; a data-path send fills the one slot the queue admits.
    wait_until(
        "the originated keepalive probe to take the control lane",
        || served.budget.control_pending() == (1, ping_len),
    )?;
    served
        .lease
        .send(Message::Ping(1))
        .map_err(|_| "a fresh queue admits its one message")?;
    assert!(
        !served.budget.writer_dead(),
        "the gated writer is live while its gate stays shut"
    );
    assert!(!served.lease.is_cancelled());

    let stray = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
        transactions: bitcoin::bip152::BlockTransactions {
            block_hash: bitcoin::BlockHash::all_zeros(),
            transactions: Vec::new(),
        },
    });
    served.client.send(&stray)?;
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        !served.lease.is_cancelled(),
        "a locally full queue defers a conditional compact reply instead of closing"
    );
    assert_eq!(
        served.budget.pending(),
        (1, ping_len),
        "an Idle compact outcome reserves and queues nothing while parked"
    );

    served.open_gate();
    assert!(
        matches!(
            read_messages(&mut served.client, 2)?.as_slice(),
            [Message::Ping(_), Message::Ping(1)]
        ),
        "the originated keepalive probe and the queued ping drain in order"
    );
    served.client.send(&Message::Ping(99))?;
    assert_eq!(
        read_messages(&mut served.client, 1)?,
        vec![Message::Pong(99)],
        "the deferred conditional was answered with nothing and the session still serves"
    );

    served.lease.cancel();
    let outcome = served.session_outcome(FAILSAFE)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

#[test]
fn conditional_local_retry_defers_then_readies_with_no_reply() -> TestResult {
    let t0 = Instant::now();
    let stray = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
        transactions: bitcoin::bip152::BlockTransactions {
            block_hash: bitcoin::BlockHash::all_zeros(),
            transactions: Vec::new(),
        },
    });
    let bound = reply_bound(&stray, false).ok_or("a reserved blocktxn")?;
    let (queue, receiver) = crate::test_support::message_channel();
    let lease = PeerLease::new_with_budget(
        queue,
        true,
        OutboundBudget::with_block_reserve(1, 1 << 20, 1),
    );
    lease
        .send(Message::Ping(1))
        .map_err(|_| "a fresh queue admits one message")?;
    let ping_len = wire_len_of(&Message::Ping(1))?;
    assert_eq!(lease.budget_handle().pending(), (1, ping_len));
    assert!(!lease.budget_handle().writer_dead());
    assert_eq!(lease.try_reserve_reply(bound).err(), Some(Refusal::Local));
    let mut peer = parked_peer(Vec::new());
    let mut keepalive = Keepalive::starting(t0);
    let mut parked_since = None;
    peer.deferred_inbound = Some(stray.clone());
    assert!(matches!(
        retry_deferred_request(
            &mut peer,
            &lease,
            &mut keepalive,
            &mut parked_since,
            false,
            t0
        ),
        DeferredStep::Waiting
    ));
    assert_eq!(peer.deferred_inbound, Some(stray.clone()));
    assert!(!lease.is_cancelled());
    assert!(parked_since.is_some());
    assert_eq!(lease.budget_handle().pending(), (1, ping_len));
    assert_eq!(receiver.try_recv(), Ok(Message::Ping(1)));
    assert_eq!(lease.budget_handle().pending(), (0, 0));
    let step = retry_deferred_request(
        &mut peer,
        &lease,
        &mut keepalive,
        &mut parked_since,
        false,
        t0,
    );
    let DeferredStep::Ready(message, Some(credit)) = step else {
        return Err("the reply is reserved once the local queue has room".into());
    };
    assert_eq!(message, stray);
    assert_eq!(peer.deferred_inbound, None);
    assert_eq!(parked_since, None);
    let mut recon = crate::compact_blocks::Reconstruction::new();
    let outcome = super::process_compact_message(
        &mut recon,
        &message,
        crate::peer::COMPACT_BLOCK_VERSION,
        None,
        Instant::now(),
    );
    assert!(matches!(outcome, crate::compact_blocks::Outcome::Idle));
    let sink = ProductionSink::new(&lease, Some(credit));
    let shared = shared_with(ScriptedChain { blocks: Vec::new() });
    let addr = bitcoin_rs_consensus::primitives::PeerEndpoint::from(([127, 0, 0, 1], 8333));
    assert!(super::handle_compact_outcome(outcome, &sink, addr, &shared, None).is_none());
    assert!(receiver.is_empty());
    assert!(!lease.is_cancelled());
    drop(sink);
    assert_eq!(lease.budget_handle().pending(), (0, 0));
    Ok(())
}

#[test]
fn unconditional_ping_on_locally_full_queue_ends() -> TestResult {
    let t0 = Instant::now();
    let (queue, _receiver) = crate::test_support::message_channel();
    let lease = PeerLease::new_with_budget(
        queue,
        true,
        OutboundBudget::with_block_reserve(1, 1 << 20, 1),
    );
    lease
        .send(Message::Ping(1))
        .map_err(|_| "a fresh queue admits one message")?;
    let mut peer = parked_peer(Vec::new());
    let mut keepalive = Keepalive::starting(t0);
    let mut parked_since = None;
    peer.deferred_inbound = Some(Message::Ping(8));
    assert!(matches!(
        retry_deferred_request(
            &mut peer,
            &lease,
            &mut keepalive,
            &mut parked_since,
            false,
            t0
        ),
        DeferredStep::Ended
    ));
    assert!(lease.is_cancelled());
    Ok(())
}

#[test]
fn conditional_local_retry_with_dead_writer_ends() {
    let t0 = Instant::now();
    let stray = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
        transactions: bitcoin::bip152::BlockTransactions {
            block_hash: bitcoin::BlockHash::all_zeros(),
            transactions: Vec::new(),
        },
    });
    let (queue, _receiver) = crate::test_support::message_channel();
    let lease = PeerLease::new(queue);
    lease.budget_handle().mark_writer_dead();
    let mut peer = parked_peer(Vec::new());
    let mut keepalive = Keepalive::starting(t0);
    let mut parked_since = None;
    peer.deferred_inbound = Some(stray);
    assert!(matches!(
        retry_deferred_request(
            &mut peer,
            &lease,
            &mut keepalive,
            &mut parked_since,
            false,
            t0
        ),
        DeferredStep::Ended
    ));
}

#[test]
fn conditional_local_wait_expires_after_timeout_interval() -> TestResult {
    let t0 = Instant::now();
    let (queue, _receiver) = crate::test_support::message_channel();
    let lease = PeerLease::new_with_budget(
        queue,
        true,
        OutboundBudget::with_block_reserve(1, 1 << 20, 1),
    );
    lease
        .send(Message::Ping(1))
        .map_err(|_| "a fresh queue admits one message")?;
    let mut peer = parked_peer(Vec::new());
    let mut keepalive = Keepalive::starting(t0);
    let mut parked_since = None;
    peer.deferred_inbound = Some(Message::BlockTxn(
        bitcoin::p2p::message_compact_blocks::BlockTxn {
            transactions: bitcoin::bip152::BlockTransactions {
                block_hash: bitcoin::BlockHash::all_zeros(),
                transactions: Vec::new(),
            },
        },
    ));
    assert!(matches!(
        retry_deferred_request(
            &mut peer,
            &lease,
            &mut keepalive,
            &mut parked_since,
            false,
            t0
        ),
        DeferredStep::Waiting
    ));
    keepalive.settle_pass(t0, &mut parked_since);
    assert!(matches!(
        retry_deferred_request(
            &mut peer,
            &lease,
            &mut keepalive,
            &mut parked_since,
            false,
            t0 + TIMEOUT_INTERVAL + Duration::from_secs(1)
        ),
        DeferredStep::Ended
    ));
    Ok(())
}

// P2P-02
#[test]
fn holding_maximum_share_leaves_room_for_second_connection() -> TestResult {
    let aggregate = Arc::new(SharedOutboundBudget::new());
    let (tx1, _rx1) = crate::test_support::message_channel();
    let lease1 = PeerLease::new(tx1).with_shared_budget(&aggregate);
    let (tx2, _rx2) = crate::test_support::message_channel();
    let lease2 = PeerLease::new(tx2).with_shared_budget(&aggregate);

    let budget1 = lease1.budget_handle();
    let max_share = budget1.max_bytes();
    let hold = budget1
        .try_charge(max_share)
        .map_err(|_| "independent oracle requires connection to hold its full share")?;
    assert!(
        matches!(budget1.try_charge(1), Err(Refusal::Local)),
        "independent oracle: exceeding connection share must yield Local refusal"
    );

    let ping = Message::Ping(1);
    lease2.send(ping).map_err(|refusal| {
        format!("independent oracle violated: second connection starved by peer holding share: {refusal:?}")
    })?;
    assert!(
        lease2.try_reserve_production().is_ok(),
        "independent oracle: aggregate bulk headroom must remain open for other peers"
    );

    drop(hold);
    Ok(())
}

// P2P-02
#[test]
fn aggregate_never_exceeds_cap_with_concurrent_reservers() -> TestResult {
    let aggregate = Arc::new(SharedOutboundBudget::new());
    let cap = aggregate.max_bytes();
    let threads = 8;
    let iterations = 200;
    let barrier = Arc::new(std::sync::Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|i| {
            let agg = Arc::clone(&aggregate);
            let bar = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let (tx, _rx) = crate::test_support::message_channel();
                let lease = PeerLease::new(tx).with_shared_budget(&agg);
                let budget = lease.budget_handle();
                bar.wait();
                let mut held = Vec::new();
                for step in 0..iterations {
                    let size = ((i + step) % 5 + 1) * 1024 * 1024;
                    if let Ok(credit) = budget.try_charge(size) {
                        let used = agg.pending();
                        assert!(
                            used <= cap,
                            "independent oracle violated: aggregate pending {used} exceeded cap {cap}"
                        );
                        held.push(credit);
                    }
                    if held.len() > 2 {
                        let _ = held.remove(0);
                    }
                    let used = agg.pending();
                    assert!(
                        used <= cap,
                        "independent oracle violated: aggregate pending {used} exceeded cap {cap}"
                    );
                }
                drop(held);
            })
        })
        .collect();

    for handle in handles {
        handle
            .join()
            .map_err(|_| "reserver thread joined cleanly")?;
    }

    assert_eq!(
        aggregate.pending(),
        0,
        "independent oracle: releasing all credits must return aggregate used bytes to 0"
    );
    Ok(())
}

// P2P-02
#[test]
fn releasing_credits_returns_used_to_zero() -> TestResult {
    let aggregate = Arc::new(SharedOutboundBudget::new());
    let (tx, _rx) = crate::test_support::message_channel();
    let lease = PeerLease::new(tx).with_shared_budget(&aggregate);
    let budget = lease.budget_handle();

    let credit = budget
        .try_charge(1_000_000)
        .map_err(|_| "independent oracle: fresh budget admits reservation")?;
    assert_eq!(
        aggregate.pending(),
        1_000_000,
        "independent oracle: aggregate pending equals charged credit"
    );
    drop(credit);
    assert_eq!(
        aggregate.pending(),
        0,
        "independent oracle: dropping credit returns aggregate pending bytes to 0"
    );
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum CompactIngressTestError {
    #[error(transparent)]
    Peer(#[from] crate::PeerError),
    #[error(transparent)]
    Compact(#[from] bitcoin::bip152::Error),
    #[error(transparent)]
    HeaderReceive(#[from] crossbeam_channel::TryRecvError),
    #[error(transparent)]
    ForwardReceive(#[from] crossbeam_channel::RecvTimeoutError),
    #[error(transparent)]
    ForwardSignal(#[from] crossbeam_channel::SendError<()>),
    #[error("missing: {0}")]
    Missing(&'static str),
    #[error("block decoder returned another command")]
    UnexpectedCommand,
    #[error("compact worker panicked: {0:?}")]
    WorkerPanicked(Box<dyn std::any::Any + Send>),
}

type CompactTestResult = Result<(), CompactIngressTestError>;

struct CompactForwarding {
    reached: crossbeam_channel::Sender<()>,
    result: parking_lot::Mutex<Option<Result<(), crossbeam_channel::SendError<()>>>>,
}

struct CompactAdmissionObserver {
    forwarding: Option<Arc<CompactForwarding>>,
}

impl super::BlockSyncObserver for CompactAdmissionObserver {
    fn announce_block(&self, _: crate::PeerSource, _: bitcoin_rs_consensus::primitives::Hash256) {}
    fn block_not_found(&self, _: crate::PeerSource, _: &[Inventory]) -> bool {
        false
    }
    fn note_header_response_received(&self, _: crate::PeerSource) {}
    fn owns_body_fetch(
        &self,
        _: crate::PeerSource,
        _: bitcoin_rs_consensus::primitives::Hash256,
    ) -> bool {
        if let Some(forwarding) = &self.forwarding {
            let result = forwarding.reached.send(());
            let delivered = result.is_ok();
            *forwarding.result.lock() = Some(result);
            return delivered;
        }
        true
    }
    fn compact_reconstruction_admissible(&self, _: crate::PeerSource, _: &Header) -> bool {
        true
    }
    fn enqueue_owned_body_fetch(
        &self,
        _: crate::PeerSource,
        _: bitcoin_rs_consensus::primitives::Hash256,
        follow_up: &mut dyn FnMut() -> bool,
    ) -> bool {
        follow_up()
    }
    fn note_stale_tip_heard(
        &self,
        _: crate::PeerSource,
        _: bitcoin_rs_consensus::primitives::Hash256,
    ) {
    }
    fn allow_extra_full_relay_dial(&self) -> bool {
        false
    }
    fn is_downloading_bodies(&self, _: crate::PeerSource) -> bool {
        true
    }
}

struct NoCompactTransactions;

impl crate::compact_blocks::CompactBlockHints for NoCompactTransactions {
    fn for_each_identity(
        &self,
        _: &mut dyn FnMut(
            bitcoin_rs_consensus::primitives::Txid,
            bitcoin_rs_consensus::primitives::Wtxid,
        ),
    ) {
    }
    fn get_tx_by_txid(
        &self,
        _: bitcoin_rs_consensus::primitives::Txid,
    ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
        None
    }
    fn get_tx_by_wtxid(
        &self,
        _: bitcoin_rs_consensus::primitives::Wtxid,
    ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
        None
    }
}

// BUD-03, BUD-07, P2P-06, SYNC-03
#[test]
fn compact_admission_refusal_preserves_header_for_ordinary_sync() -> CompactTestResult {
    for remaining in [0, crate::compact_blocks::MAX_PENDING_RETAINED_BYTES] {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let message = Message::CmpctBlock(CmpctBlock {
            compact_block: HeaderAndShortIds::from_block(&block, 7, 2, &[])?,
        });
        let expected = crate::compact_blocks::native_header(&block.header)
            .ok_or(CompactIngressTestError::Missing("native header"))?;
        let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
        shared.block_sync = Some(Arc::new(CompactAdmissionObserver { forwarding: None }));
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        shared.headers_tx = headers_tx;
        let ledger = shared.block_memory.ledger();
        let held = shared
            .block_memory
            .try_reserve(ledger.capacity() - remaining)?;
        let (queue, _receiver) = crate::test_support::message_channel();
        let lease = PeerLease::new(queue);
        let endpoint = bitcoin_rs_consensus::primitives::PeerEndpoint::from(([127, 0, 0, 1], 8333));
        let mut reconstruction = crate::compact_blocks::Reconstruction::new();
        super::process_compact_wire_message(
            &message,
            &mut reconstruction,
            Some(2),
            Some(&NoCompactTransactions),
            &ProductionSink::new(&lease, None),
            endpoint,
            &shared,
        );
        let delivered = headers_rx.try_recv()?;
        assert_eq!(delivered.headers, vec![expected]);
        assert_eq!(delivered.source, Some(lease.source(Some(endpoint))));
        assert!(!delivered.wire_response);
        assert!(
            headers_rx.is_empty(),
            "one discovery announcement per refused compact block"
        );
        assert_eq!(reconstruction.pending_len(), 0);
        drop(held);
        assert!(
            ledger.try_take(ledger.capacity()),
            "refused optional work retains no reservation"
        );
        ledger.give_back(ledger.capacity());
    }
    Ok(())
}

// BUD-01, BUD-06
#[test]
fn compact_forward_backpressure_keeps_source_and_image_charged() -> CompactTestResult {
    for (completion, deliver) in [
        ("cmpctblock", true),
        ("blocktxn", true),
        ("cmpctblock", false),
        ("blocktxn", false),
    ] {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut reconstruction = crate::compact_blocks::Reconstruction::new();
        let compact = HeaderAndShortIds::from_block(&block, 7, 2, &[])?;
        let message = if completion == "cmpctblock" {
            Message::CmpctBlock(CmpctBlock {
                compact_block: compact,
            })
        } else {
            let mut missing = compact;
            let keys = ShortId::calculate_siphash_keys(&block.header, 7);
            missing.prefilled_txs.clear();
            missing.short_ids = vec![ShortId::with_siphash_keys(
                block.txdata[0].compute_wtxid().as_byte_array(),
                keys,
            )];
            assert!(matches!(
                reconstruction.receive_cmpctblock(
                    &CmpctBlock {
                        compact_block: missing
                    },
                    2,
                    &NoCompactTransactions,
                    Instant::now(),
                ),
                crate::compact_blocks::Outcome::RequestMissing(_)
            ));
            Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
                transactions: bitcoin::bip152::BlockTransactions {
                    block_hash: block.block_hash(),
                    transactions: block.txdata.clone(),
                },
            })
        };
        let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
        let (forwarding_tx, forwarding_rx) = crossbeam_channel::bounded(1);
        let forwarding = Arc::new(CompactForwarding {
            reached: forwarding_tx,
            result: parking_lot::Mutex::new(None),
        });
        shared.block_sync = Some(Arc::new(CompactAdmissionObserver {
            forwarding: Some(Arc::clone(&forwarding)),
        }));
        let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(0);
        shared.blocks_tx = blocks_tx;
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        shared.headers_tx = headers_tx;
        let ledger = Arc::clone(shared.block_memory.ledger());
        let payload = bytes::Bytes::from(bitcoin::consensus::serialize(&block));
        let Message::Block(image) = crate::wire::decode_payload("block", &payload)? else {
            return Err(CompactIngressTestError::UnexpectedCommand);
        };
        let image_bytes = image.bytes().len() + image.retained_heap_bytes();
        drop(image);
        let mut frame = Vec::new();
        crate::wire::write_message(&mut frame, MAGIC, &message)?;
        let mut peer = crate::Peer::new(std::io::Cursor::new(frame), MAGIC);
        peer.state = crate::PeerState::Ready;
        let (source_message, raw, source_credit) = peer
            .read_message_bounded(&shared.block_memory, || false)?
            .ok_or(CompactIngressTestError::Missing(
                "one compact source message",
            ))?;
        let used_bytes = || {
            let mut available = 0;
            let mut upper = ledger.capacity();
            while available < upper {
                let probe = available + (upper - available).div_ceil(2);
                if ledger.try_take(probe) {
                    ledger.give_back(probe);
                    available = probe;
                } else {
                    upper = probe - 1;
                }
            }
            ledger.capacity() - available
        };
        let source_bytes = used_bytes();
        assert!(
            source_bytes > 0,
            "bounded receive must charge its live source"
        );
        let (queue, _receiver) = crate::test_support::message_channel();
        let lease = PeerLease::new(queue);
        let source = (source_credit, source_message, raw);
        let worker = std::thread::spawn(move || {
            let (source_credit, source_message, raw) = source;
            super::process_compact_wire_message(
                &source_message,
                &mut reconstruction,
                Some(2),
                Some(&NoCompactTransactions),
                &ProductionSink::new(&lease, None),
                bitcoin_rs_consensus::primitives::PeerEndpoint::from(([127, 0, 0, 1], 8333)),
                &shared,
            );
            drop(source_message);
            drop(raw);
            drop(source_credit);
        });
        forwarding_rx.recv_timeout(FAILSAFE)?;
        let blocked_bytes = used_bytes();
        let inbound = if deliver {
            Some(blocks_rx.recv_timeout(FAILSAFE)?)
        } else {
            drop(blocks_rx);
            None
        };
        worker
            .join()
            .map_err(CompactIngressTestError::WorkerPanicked)?;
        forwarding
            .result
            .lock()
            .take()
            .ok_or(CompactIngressTestError::Missing(
                "forwarding observer result",
            ))??;
        let downstream_bytes = used_bytes();
        drop(inbound);
        assert_eq!(
            blocked_bytes,
            source_bytes + image_bytes,
            "{completion}: blocked forwarding retains both source and reconstructed image"
        );
        assert_eq!(
            downstream_bytes,
            if deliver { image_bytes } else { 0 },
            "{completion}: source disposal leaves only the delivered image charged"
        );
        assert!(
            ledger.try_take(ledger.capacity()),
            "all retained allocations released"
        );
        ledger.give_back(ledger.capacity());
    }
    Ok(())
}

// BUD-06
#[test]
fn refused_block_forward_keeps_image_charged_until_backing_disposal() -> CompactTestResult {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct ImageBacking {
        bytes: Vec<u8>,
        ledger: Arc<dyn crate::inbound::block_memory::IngressLedger>,
        charge: Arc<AtomicUsize>,
        observed: Arc<AtomicBool>,
    }

    impl AsRef<[u8]> for ImageBacking {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for ImageBacking {
        fn drop(&mut self) {
            let headroom = self.ledger.capacity() - self.charge.load(Ordering::Acquire);
            let admitted_headroom = self.ledger.try_take(headroom);
            let admitted_extra = self.ledger.try_take(1);
            if admitted_extra {
                self.ledger.give_back(1);
            }
            if admitted_headroom {
                self.ledger.give_back(headroom);
            }
            self.observed
                .store(admitted_headroom && !admitted_extra, Ordering::Release);
        }
    }

    let mut shared = shared_with(ScriptedChain { blocks: Vec::new() });
    shared.block_sync = None;
    let ledger = Arc::clone(shared.block_memory.ledger());
    let charge = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(AtomicBool::new(false));
    let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let raw = bytes::Bytes::from_owner(ImageBacking {
        bytes: bitcoin::consensus::serialize(&block),
        ledger: Arc::clone(&ledger),
        charge: Arc::clone(&charge),
        observed: Arc::clone(&observed),
    });
    let Message::Block(image) = crate::wire::decode_payload("block", &raw)? else {
        return Err(CompactIngressTestError::UnexpectedCommand);
    };
    let image_bytes = image.bytes().len() + image.retained_heap_bytes();
    let image_credit = shared.block_memory.try_reserve(image_bytes)?;
    charge.store(image_bytes, Ordering::Release);
    drop(raw);
    let (queue, _receiver) = crate::test_support::message_channel();
    let lease = PeerLease::new(queue);
    let endpoint = bitcoin_rs_consensus::primitives::PeerEndpoint::from(([127, 0, 0, 1], 8333));
    let source = lease.source(Some(endpoint));
    let hash = bitcoin_rs_consensus::primitives::Hash256::from(image.block_hash());
    let forwards: Vec<_> =
        (0..crate::connection::MAX_UNSOLICITED_BLOCK_FORWARDS)
            .map(|_| {
                lease.admit_block_forward(source, hash, false).ok_or(
                    CompactIngressTestError::Missing("unsolicited forwarding slot"),
                )
            })
            .collect::<Result<_, _>>()?;

    shared.send_block(&lease, endpoint, image, Some(image_credit));

    assert!(
        observed.load(Ordering::Acquire),
        "final image backing disposal must observe its complete retained-image charge"
    );
    assert!(
        ledger.try_take(ledger.capacity()),
        "refused image releases its full charge"
    );
    ledger.give_back(ledger.capacity());
    drop(forwards);
    Ok(())
}
