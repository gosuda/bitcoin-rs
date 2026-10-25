//! The node's aggregate outbound budget never ends a session. A request whose
//! reply cannot be reserved is deferred and answered once, a parked tail and
//! the parked misses are paid for before they are built, the refused time is
//! not silence, and the bulk margin keeps control traffic flowing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::bip152::{BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_compact_blocks::{CmpctBlock, GetBlockTxn};
use bitcoin_rs_primitives::Header;

use super::getdata_pause_tests::{
    FAILSAFE, MAGIC, ScriptedChain, Served, TestResult, WriterKind, block, inventory_of,
    parked_peer, read_messages, scripted, shared_with, wire_len_of,
};
use super::{
    DeferredStep, Keepalive, KeepaliveAction, ParkedStep, ProductionSink, TIMEOUT_INTERVAL,
    notfound_wire_bound, reply_bound, retry_deferred_request, step_parked_getdata,
};
use crate::connection::{OutboundBudget, Refusal, SharedOutboundBudget};
use crate::test_support::hog;
use crate::{Message, PeerLease};

/// `headroom` reserves once and reuses what it holds, so a run of misses
/// charges the aggregate once; sending spends the credit and shrinks it to
/// the frame it travels with.
#[test]
fn headroom_retains_one_credit() -> TestResult {
    let reserve = 1_000;
    // The aggregate's bulk limit is exactly one reservation.
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

/// The misses are reserved before the `notfound` is built: a refusal leaves
/// the list as it was, charges nothing, reports a stall instead of an error,
/// and the list goes out intact once the aggregate has room.
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

/// The reservation taken before a reply is built covers the largest `pong`,
/// `headers` or `addr`/`addrv2` reply the loop can build.
#[test]
fn reply_bound_covers_actual_replies() -> TestResult {
    // `ping` answers with a `pong` of the same size.
    assert_eq!(
        reply_bound(&Message::Ping(1), false),
        Some(wire_len_of(&Message::Pong(u64::MAX))?)
    );

    // `getheaders` answers with at most the maximum number of headers.
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

    // `getaddr` is reserved for only while it is answered from the book, in
    // either encoding, at its worst-case row size.
    assert_eq!(reply_bound(&Message::GetAddr, false), None);
    let socket = std::net::SocketAddr::from(([1, 2, 3, 4], 8333));
    let addr_v1 = Message::Addr(vec![
        (0, Address::new(&socket, ServiceFlags::NONE));
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

/// A compact-block message is answered with a follow-up request the loop
/// reserves for before dispatch: a `getblocktxn` naming every slot at worst,
/// or a one-item `getdata` fallback.
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

    // `blocktxn` can only fall back to a one-item `getdata`.
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

/// The parked misses are reserved at the exact length of the `notfound` that
/// will carry them, across the compact-size boundary.
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

/// Only the aggregate's refusal is a stall. Silence inside it is not counted,
/// silence after it is, and a refusal of the connection's own queue never
/// opens one.
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

/// The deferred-retry harness: the parked peer, the lease under test, and
/// the stall clock its retries charge against. The aggregate-starved lease,
/// the full local queue, the dead writer, and the stall markers rotate
/// through the same fields phase by phase, so every transition below runs
/// against the exact state the previous one left behind.
struct DeferredHarness {
    lease: PeerLease,
    peer: crate::Peer<std::io::Cursor<Vec<u8>>>,
    keepalive: Keepalive,
    parked_since: Option<Instant>,
}

impl DeferredHarness {
    /// Parks `message` as the deferred inbound and retries it under the
    /// current lease and stall clock; `getaddr` is never answerable here.
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

    /// Retries whatever the previous step left deferred, without parking
    /// anything new.
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

/// A request whose reply the aggregate refuses is kept and retried; the
/// connection's own full queue, a dead writer and an old pause outside a
/// stall each keep their existing rule.
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

    // The connection's own full queue closes it, as before.
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

    // A dead writer ends it without waiting.
    let (queue, _receiver) = crate::test_support::message_channel();
    harness.lease = PeerLease::new(queue);
    harness.lease.budget_handle().mark_writer_dead();
    assert!(matches!(
        harness.retry(Some(Message::Ping(9)), t0),
        DeferredStep::Ended
    ));

    // An old pause outside a stall expires; inside the stall that began with
    // it, it does not.
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

/// Runs `request` against a session whose aggregate refuses its reply and
/// checks that nothing is queued meanwhile, the session lives, and the single
/// reply arrives once the aggregate drains.
fn answered_once_after_the_aggregate_drains(request: &Message, expected: Message) -> TestResult {
    let bound = reply_bound(request, true).ok_or("a request-scoped reply")?;
    let aggregate = Arc::new(SharedOutboundBudget::with_limits(4 * bound, 0));
    // Other connections' queued bytes leave one byte too few for the reply.
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

    // The writer's gate stays shut while the aggregate is full, so a reply
    // queued too early would stay charged and show in `pending`.
    served.client.send(request)?;
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        served.budget.pending(),
        (0, 0),
        "{request:?}: no reply is reserved or queued while the aggregate is full"
    );
    assert!(
        !served.lease.is_cancelled(),
        "{request:?}: the aggregate never ends a session"
    );

    drop(hold);
    served.open_gate();
    assert_eq!(read_messages(&mut served.client, 1)?, vec![expected]);
    served.client.send(&Message::Ping(99))?;
    assert_eq!(
        read_messages(&mut served.client, 1)?,
        vec![Message::Pong(99)],
        "{request:?}: the deferred request was answered exactly once"
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

/// A bulk tail the aggregate cannot take parks without touching the lease,
/// control sends still fit in the bulk margin, and the tail is served once
/// the aggregate drains.
#[test]
fn a_bulk_tail_parked_on_the_aggregate_leaves_the_margin_for_control() -> TestResult {
    let block_a = block(11);
    let entry = scripted(&block_a);
    let block_len = wire_len_of(&Message::BlockPayload(entry.1.clone()))?;
    // Bulk limit nine blocks, margin one: eight blocks and a byte of other
    // connections' bytes leave no bulk room for one more reservation.
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

    // The writer's gate stays shut, so everything charged stays visible: the
    // parked tail holds no reservation and queues no body, while the control
    // message still fits in the margin.
    served
        .client
        .send(&Message::GetData(vec![inventory_of(&block_a)]))?;
    std::thread::sleep(Duration::from_millis(300));
    let ping_len = wire_len_of(&Message::Ping(3))?;
    served
        .lease
        .send(Message::Ping(3))
        .map_err(|_| "the margin keeps control traffic flowing")?;
    assert_eq!(served.budget.pending(), (1, ping_len));
    assert_eq!(aggregate.pending(), 8 * block_len + 1 + ping_len);
    assert!(
        !served.lease.is_cancelled(),
        "a parked bulk tail never cancels the lease"
    );

    served.open_gate();
    assert_eq!(
        read_messages(&mut served.client, 1)?,
        vec![Message::Ping(3)]
    );
    drop(hold);
    assert_eq!(
        read_messages(&mut served.client, 1)?,
        vec![Message::Block(block_a)],
        "the tail is served once the aggregate has room"
    );

    served.lease.cancel();
    let outcome = served.session_outcome(FAILSAFE)?;
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

/// A conditional compact reply defers on a locally full queue with a live writer.
///
/// A stray `blocktxn` has no pending reconstruction, so the real
/// `process_compact_message` returns `Idle` and `handle_compact_outcome`
/// sends nothing, yet `reply_bound` still reserves for it. One `Idle` probe
/// covers the conditional class: `CmpctBlock` shares the same bound and the
/// same fresh/retry gate. The fresh gate and the deferred retry must both
/// defer it instead of closing, while `Ping` keeps its unconditional
/// high-water close
/// (pinned by `deferred_request_retries_and_keeps_the_existing_local_rules`)
/// and a dead writer still ends the session. The local wait counts toward
/// the timeout; only a shared refusal opens a stall.
///
/// This is a bounded real-socket smoke: it parks one conditional against a
/// full local queue, observes that nothing is cancelled or queued, then
/// drains and proves the session still serves. The sleep only bounds the
/// live-session poll window and proves no causal barrier. The deterministic
/// witness that the retry defers and then readies with no reply is
/// `conditional_local_retry_defers_then_readies_with_no_reply`.
#[test]
fn conditional_compact_defers_on_locally_full_queue() -> TestResult {
    // One-slot local queue, no aggregate: the next reservation fails Local.
    let mut served = Served::start(
        shared_with(ScriptedChain { blocks: Vec::new() }),
        OutboundBudget::with_block_reserve(1, 1 << 20, 1),
        &WriterKind::Gated,
    )?;
    let ping_len = wire_len_of(&Message::Ping(1))?;
    served
        .lease
        .send(Message::Ping(1))
        .map_err(|_| "a fresh queue admits one message")?;
    assert_eq!(served.budget.pending(), (1, ping_len));
    assert!(
        !served.budget.writer_dead(),
        "the gated writer is live while its gate stays shut"
    );
    assert!(!served.lease.is_cancelled());

    // Stray `blocktxn`: no pending entry, so the real reconstruction returns
    // `Idle` and sends nothing.
    let stray = Message::BlockTxn(bitcoin::p2p::message_compact_blocks::BlockTxn {
        transactions: bitcoin::bip152::BlockTransactions {
            block_hash: bitcoin::BlockHash::all_zeros(),
            transactions: Vec::new(),
        },
    });
    // The single conditional arrives while the local queue is full. The
    // session must park instead of closing: the fresh gate defers, and the
    // deferred retry keeps waiting with a live writer. The sleep only bounds
    // the live-session poll window; it is not a barrier, so this test claims
    // only the parked state, not that the retry fired.
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

    // Draining the filler proves nothing spurious was queued: only the filler
    // reaches the peer, then the session still serves.
    served.open_gate();
    assert_eq!(
        read_messages(&mut served.client, 1)?,
        vec![Message::Ping(1)]
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

/// Deterministic witness for the conditional local retry with a live writer:
/// a locally full queue defers (`Waiting`) without cancelling, then readies
/// once the queue drains and the stray `blocktxn` answers nothing (`Idle`).
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
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
    assert!(
        super::handle_compact_outcome(
            outcome,
            &sink,
            addr,
            Some(crate::PeerEndpoint::Ip(addr)),
            &shared
        )
        .is_none()
    );
    assert!(receiver.is_empty());
    assert!(!lease.is_cancelled());
    drop(sink);
    assert_eq!(lease.budget_handle().pending(), (0, 0));
    Ok(())
}

/// An unconditional `Ping` on a locally full queue still ends and cancels.
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

/// A conditional compact request with a dead writer ends instead of waiting.
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

/// A fresh local wait expires once parked past `TIMEOUT_INTERVAL` plus a second.
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
