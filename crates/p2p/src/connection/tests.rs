use super::{
    OutboundBudget, OutboundCredit, OutboundRefusal, PeerLease, QueuedFrame, Refusal,
    SharedOutboundBudget,
};
use bitcoin_rs_primitives::PeerEndpoint;
use crossbeam_channel::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn standalone(max_messages: usize, max_bytes: usize, reserve: usize) -> Arc<OutboundBudget> {
    Arc::new(OutboundBudget::with_block_reserve(
        max_messages,
        max_bytes,
        reserve,
    ))
}

fn charge(budget: &Arc<OutboundBudget>, bytes: usize) -> OutboundCredit {
    budget
        .try_charge(bytes)
        .unwrap_or_else(|refusal| panic!("charge of {bytes} refused: {refusal:?}"))
}

fn reserve(budget: &Arc<OutboundBudget>) -> OutboundCredit {
    budget
        .try_reserve_production()
        .unwrap_or_else(|refusal| panic!("production reservation refused: {refusal:?}"))
}

fn shared_lease_with_reserve(
    shared: &Arc<SharedOutboundBudget>,
    reserve_bytes: usize,
) -> (PeerLease, Receiver<QueuedFrame>) {
    let (tx, rx) = crossbeam_channel::unbounded();
    let lease = PeerLease::new_with_budget(
        tx,
        false,
        OutboundBudget::with_block_reserve(100, 1_000_000, reserve_bytes),
    )
    .with_shared_budget(shared);
    (lease, rx)
}

fn shared_lease(shared: &Arc<SharedOutboundBudget>) -> (PeerLease, Receiver<QueuedFrame>) {
    let (tx, rx) = crossbeam_channel::unbounded();
    (PeerLease::new(tx).with_shared_budget(shared), rx)
}

fn peer_info(
    addr: crate::PeerEndpoint,
    conn_time: u64,
) -> Result<crate::PeerInfo, Box<dyn std::error::Error>> {
    let ip = addr
        .as_ip()
        .ok_or_else(|| std::io::Error::other("ip test peer"))?;
    Ok(crate::PeerInfo {
        addr: addr.into(),
        endpoint: Some(addr),
        network: addr.net(),
        version: 70_016,
        wtxid_relay: false,
        relay_transactions: true,
        compact_block_relay: false,
        send_headers: false,
        services: 0,
        user_agent: String::from("/test/"),
        start_height: 0,
        best_known_height: 0,
        conn_time,
        inbound: false,
        addr_bind: crate::TransportRemote::new(ip),
        time_offset: 0,
        counters: std::sync::Arc::new(crate::PeerCounters::default()),
        transport: crate::TransportProtocol::V1,
    })
}

#[test]
fn lease_ids_are_unique_and_clones_keep_identity() {
    let (first_tx, _first_rx) = crossbeam_channel::unbounded();
    let (second_tx, _second_rx) = crossbeam_channel::unbounded();
    let first = PeerLease::new(first_tx);
    let first_clone = first.clone();
    let second = PeerLease::new(second_tx);

    assert!(first.same_connection(&first_clone));
    assert!(!first.same_connection(&second));
}

#[test]
fn cancellation_is_shared_by_clones() {
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = PeerLease::new(tx);
    let clone = lease.clone();

    lease.cancel();

    assert!(clone.is_cancelled());
}

#[test]
fn node_ids_are_stable_and_distinct() {
    let (first_tx, _first_rx) = crossbeam_channel::unbounded();
    let (second_tx, _second_rx) = crossbeam_channel::unbounded();
    let first = PeerLease::new(first_tx);
    let clone = first.clone();
    let second = PeerLease::new(second_tx);

    assert_eq!(first.node_id(), clone.node_id());
    assert_ne!(first.node_id(), second.node_id());
}

#[test]
fn direction_distinguishes_inbound_from_outbound_leases() {
    let (tx, _rx) = crossbeam_channel::unbounded();
    assert!(!PeerLease::new(tx.clone()).is_inbound());
    assert!(PeerLease::new_inbound(tx).is_inbound());
}

#[test]
fn stale_connection_cannot_publish_over_replacement() -> Result<(), Box<dyn std::error::Error>> {
    let table = crate::PeerTable::new();
    let addr = PeerEndpoint::from(([127, 0, 0, 1], 18_450));
    let (old_tx, _old_rx) = crossbeam_channel::unbounded();
    let old = PeerLease::new(old_tx);
    assert!(!table.register(addr, old.clone()));
    assert!(table.publish_info(addr, &old, peer_info(addr, 1)?));

    let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
    let replacement = PeerLease::new(replacement_tx);
    assert!(table.register(addr, replacement.clone()));
    assert!(old.is_cancelled());
    assert_eq!(table.infos(), []);
    assert_eq!(table.ready_source(addr), None);
    assert!(!table.publish_info(addr, &old, peer_info(addr, 2)?));
    assert_eq!(table.infos(), []);

    assert!(table.publish_info(addr, &replacement, peer_info(addr, 3)?));
    assert_eq!(table.infos(), vec![peer_info(addr, 3)?]);
    assert_eq!(
        table.ready_source(addr),
        Some(replacement.source(Some(addr)))
    );
    assert!(
        table
            .lease(addr)
            .is_some_and(|current| current.same_connection(&replacement))
    );
    Ok(())
}

#[test]
fn stale_disconnect_source_preserves_replacement() -> Result<(), Box<dyn std::error::Error>> {
    let table = crate::PeerTable::new();
    let addr = PeerEndpoint::from(([127, 0, 0, 1], 18_451));
    let (old_tx, _old_rx) = crossbeam_channel::unbounded();
    let old = PeerLease::new(old_tx);
    table.register(addr, old.clone());
    let stale_source = old.source(Some(addr));

    let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
    let replacement = PeerLease::new(replacement_tx);
    table.register(addr, replacement.clone());
    table.publish_info(addr, &replacement, peer_info(addr, 2)?);

    assert!(!table.disconnect_source(stale_source));
    assert!(!replacement.is_cancelled());
    assert!(table.is_connected(addr));
    assert_eq!(table.infos(), vec![peer_info(addr, 2)?]);

    assert!(table.disconnect_source(replacement.source(Some(addr))));
    assert!(replacement.is_cancelled());
    assert!(!table.is_connected(addr));
    assert_eq!(table.infos(), []);
    Ok(())
}

#[test]
fn ready_snapshot_keeps_identity_across_same_address_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let table = crate::PeerTable::new();
    let addr = PeerEndpoint::from(([127, 0, 0, 1], 18_452));
    let (old_tx, _old_rx) = crossbeam_channel::unbounded();
    let old = PeerLease::new(old_tx);
    table.register(addr, old.clone());
    assert!(table.publish_info(addr, &old, peer_info(addr, 1)?));
    let Some(snapshot) = table.ready_peers().pop() else {
        return Err(std::io::Error::other("ready peer snapshot missing").into());
    };

    let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
    let replacement = PeerLease::new(replacement_tx);
    table.register(addr, replacement.clone());

    assert!(table.lease_source(snapshot).is_none());
    assert!(table.lease_source(replacement.source(Some(addr))).is_some());
    Ok(())
}

#[test]
fn block_production_reserve_admits_worst_case_block() {
    let Ok(block_size) = usize::try_from(bitcoin_rs_consensus::MAX_BLOCK_SERIALIZED_SIZE) else {
        panic!("MAX_BLOCK_SERIALIZED_SIZE exceeds usize on this platform")
    };
    let worst_case_wire = crate::wire::HEADER_LEN + block_size;
    assert_eq!(
        super::BLOCK_PRODUCTION_RESERVE_BYTES,
        worst_case_wire,
        "reserve must equal header + consensus max block size"
    );
    let budget = standalone(
        1,
        super::BLOCK_PRODUCTION_RESERVE_BYTES,
        super::BLOCK_PRODUCTION_RESERVE_BYTES,
    );
    let credit = charge(&budget, worst_case_wire);
    assert_eq!(
        credit.bytes(),
        worst_case_wire,
        "a worst-case block must be admissible when the byte cap equals the reserve"
    );
    drop(credit);

    let progress = standalone(4, 100, 1_000);
    assert!(progress.may_reserve_production());

    let reserve_bytes = 100;
    let budget = standalone(10, 3 * reserve_bytes, reserve_bytes);
    assert!(budget.may_reserve_production());
    let first = charge(&budget, reserve_bytes);
    assert!(budget.may_reserve_production());
    let second = charge(&budget, reserve_bytes);
    assert!(budget.may_reserve_production());
    let third = charge(&budget, reserve_bytes);
    assert!(!budget.may_reserve_production());
    assert_eq!(budget.try_reserve_production().err(), Some(Refusal::Local));
    drop(first);
    assert!(budget.may_reserve_production());
    drop((second, third));
}

#[test]
fn headroom_needs_a_free_item_slot_as_well_as_the_byte_reserve() {
    let budget = standalone(2, 1_000_000, 100);
    assert!(budget.may_reserve_production(), "empty queue");
    let first = charge(&budget, 10);
    assert!(budget.may_reserve_production(), "one slot is free");
    let second = charge(&budget, 10);
    assert!(
        !budget.may_reserve_production(),
        "no item slot is free, however few bytes are queued"
    );
    drop(first);
    assert!(budget.may_reserve_production());
    drop(second);
    assert!(
        budget.may_reserve_production(),
        "an empty queue admits one oversized message"
    );
}

#[test]
fn may_charge_is_the_admit_condition_without_the_reserve() {
    let reserve_bytes = 100;
    let budget = standalone(3, 3 * reserve_bytes, reserve_bytes);
    assert!(budget.may_charge(10));
    let first = charge(&budget, 2 * reserve_bytes + 50);
    assert!(
        !budget.may_reserve_production(),
        "no room left for a worst-case block"
    );
    assert!(
        budget.may_charge(10),
        "a short control message still fits below both caps"
    );
    let second = charge(&budget, 2 * reserve_bytes);
    assert!(
        !budget.may_charge(10),
        "the byte cap is reached: a charge would refuse"
    );
    drop(second);
    let third = charge(&budget, 10);
    let fourth = charge(&budget, 10);
    assert!(
        !budget.may_charge(10),
        "the item cap is reached: a charge would refuse"
    );
    drop((first, third, fourth));
}

#[test]
fn outbound_budget_refuses_at_exact_item_cap_and_byte_cap() {
    let ping_len = wire_len_of(&crate::Message::Ping(1));

    let items = standalone(2, 100 * ping_len, 0);
    let first = charge(&items, ping_len);
    let second = charge(&items, ping_len);
    assert_eq!(items.try_charge(ping_len).err(), Some(Refusal::Local));
    assert_eq!(items.pending(), (2, 2 * ping_len));
    drop((first, second));
    assert_eq!(items.pending(), (0, 0));

    let bytes = standalone(100, 2 * ping_len, 0);
    let first = charge(&bytes, ping_len);
    let second = charge(&bytes, ping_len);
    assert_eq!(bytes.try_charge(ping_len).err(), Some(Refusal::Local));
    assert_eq!(bytes.pending(), (2, 2 * ping_len));
    drop((first, second));
    assert_eq!(bytes.pending(), (0, 0));
}

#[test]
fn oversized_single_message_admits_on_empty_local_queue() {
    let budget = standalone(10, 100, 0);

    let oversized = charge(&budget, 1_000);
    assert_eq!(budget.pending(), (1, 1_000));
    assert_eq!(budget.try_charge(1).err(), Some(Refusal::Local));
    drop(oversized);
    let next = charge(&budget, 1);
    drop(next);
    assert_eq!(budget.pending(), (0, 0));
}

#[test]
fn saturated_send_cancels_lease_and_returns_message() {
    let (tx, _rx) = crossbeam_channel::unbounded();
    let first = crate::Message::Ping(1);
    let second = crate::Message::Ping(2);
    let lease = PeerLease::new_with_budget(
        tx,
        false,
        OutboundBudget::with_block_reserve(1, 1_000_000, 0),
    );

    assert!(lease.send(first).is_ok());
    assert_eq!(
        lease.send(second.clone()),
        Err(OutboundRefusal::Closed(second))
    );
    assert!(lease.is_cancelled());
}

#[test]
fn full_channel_send_cancels_lease_and_returns_message() {
    let (tx, _rx) = crossbeam_channel::bounded(1);
    let lease = PeerLease::new(tx);
    let ping_len = wire_len_of(&crate::Message::Ping(1));

    assert!(lease.send(crate::Message::Ping(1)).is_ok());
    let message = crate::Message::Ping(2);
    assert_eq!(
        lease.send(message.clone()),
        Err(OutboundRefusal::Closed(message))
    );
    assert!(lease.is_cancelled());
    assert_eq!(
        lease.budget_handle().pending(),
        (1, ping_len),
        "the refused frame returned its charge; the queued frame keeps its own"
    );
}

#[test]
fn disconnected_channel_send_cancels_lease_and_returns_charge() {
    let (tx, rx) = crossbeam_channel::bounded(1);
    drop(rx);
    let lease = PeerLease::new(tx);

    let message = crate::Message::Ping(3);
    assert_eq!(
        lease.send(message.clone()),
        Err(OutboundRefusal::Closed(message))
    );
    assert!(lease.is_cancelled());
    assert_eq!(lease.budget_handle().pending(), (0, 0));
}

#[test]
fn bip434_features_never_enter_the_post_handshake_queue() {
    for reserved in [false, true] {
        let shared = Arc::new(SharedOutboundBudget::with_limits(10_000, 1_000));
        let (lease, rx) = shared_lease_with_reserve(&shared, 1_000);
        let message = crate::Message::Feature(crate::feature::FeatureAnnouncement::bip332(true));
        let credit = reserved.then(|| reserve(&lease.budget_handle()));
        let (other, _rx) = shared_lease_with_reserve(&shared, 1_000);
        let held = charge(&other.budget_handle(), 10_000 - shared.pending());
        let result = match credit {
            Some(credit) => lease.send_with(credit, message.clone()),
            None => lease.send(message.clone()),
        };
        assert_eq!(result, Err(OutboundRefusal::Closed(message)));
        assert!(lease.is_cancelled());
        assert!(rx.try_recv().is_err());
        assert_eq!(lease.budget_handle().pending(), (0, 0));
        drop(held);
        assert_eq!(shared.pending(), 0);
    }
}

#[test]
fn cancelled_lease_refuses_send() {
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = PeerLease::new(tx);
    lease.cancel();

    assert_eq!(
        lease.send(crate::Message::Verack),
        Err(OutboundRefusal::Closed(crate::Message::Verack))
    );
}

#[test]
fn strict_cap_no_empty_queue_bypass() {
    let shared = Arc::new(SharedOutboundBudget::with_limits(100, 0));
    let (hog, _hog_rx) = shared_lease(&shared);
    let hog_credit = charge(&hog.budget_handle(), 100);
    let (other, _other_rx) = shared_lease(&shared);

    let message = crate::Message::Ping(1);
    assert_eq!(
        other.send(message.clone()),
        Err(OutboundRefusal::Saturated(message))
    );
    assert!(!other.is_cancelled());
    assert_eq!(other.budget_handle().pending(), (0, 0));
    assert_eq!(shared.pending(), 100, "the cap is never exceeded");

    drop(hog_credit);
    assert_eq!(shared.pending(), 0);
    assert!(other.send(crate::Message::Ping(2)).is_ok());
}

#[test]
fn reservation_is_the_admission() {
    let reserve_bytes = 100;
    let margin = 40;
    for (max, admitted) in [
        (2 * reserve_bytes - 1 + margin, 1),
        (2 * reserve_bytes + margin, 2),
    ] {
        let shared = Arc::new(SharedOutboundBudget::with_limits(max, margin));
        let (lease, _rx) = shared_lease_with_reserve(&shared, reserve_bytes);
        let budget = lease.budget_handle();
        let mut held = Vec::new();
        while let Ok(credit) = budget.try_reserve_production() {
            held.push(credit);
        }
        assert_eq!(held.len(), admitted);
        assert_eq!(budget.try_reserve_production().err(), Some(Refusal::Shared));
        assert!(!lease.is_cancelled(), "a shared refusal cancels nothing");
        assert_eq!(shared.pending(), admitted * reserve_bytes);
        assert_eq!(budget.pending(), (admitted, admitted * reserve_bytes));
    }
}

#[test]
fn concurrent_reservations_never_exceed_cap() {
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let reserve_bytes = 100;
    let margin = 50;
    let max = 1_000 + margin;
    let shared = Arc::new(SharedOutboundBudget::with_limits(max, margin));
    let threads = 32;
    let start = Arc::new(Barrier::new(threads + 1));
    let stop = Arc::new(AtomicBool::new(false));
    let peak = Arc::new(AtomicUsize::new(0));
    let sampler = {
        let shared = Arc::clone(&shared);
        let stop = Arc::clone(&stop);
        let peak = Arc::clone(&peak);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                peak.fetch_max(shared.pending(), Ordering::AcqRel);
            }
        })
    };
    let mut racers = Vec::with_capacity(threads);
    for _ in 0..threads {
        let start = Arc::clone(&start);
        let (lease, rx) = shared_lease_with_reserve(&shared, reserve_bytes);
        racers.push(std::thread::spawn(move || {
            start.wait();
            let credit = lease.budget_handle().try_reserve_production().ok();
            (lease, rx, credit)
        }));
    }
    start.wait();
    let results: Vec<_> = racers
        .into_iter()
        .map(|racer| {
            racer
                .join()
                .unwrap_or_else(|_| panic!("racing reservation thread panicked"))
        })
        .collect();
    stop.store(true, Ordering::Release);
    sampler
        .join()
        .unwrap_or_else(|_| panic!("sampler thread panicked"));

    let admitted = results
        .iter()
        .filter(|(_, _, credit)| credit.is_some())
        .count();
    assert_eq!(admitted, 1_000 / reserve_bytes);
    assert_eq!(shared.pending(), admitted * reserve_bytes);
    assert!(
        peak.load(Ordering::Acquire) <= max,
        "the counter never exceeded the cap, even transiently"
    );
    drop(results);
    assert_eq!(shared.pending(), 0);
}

#[test]
fn shrink_and_drop_wake_waiters() {
    let shared = Arc::new(SharedOutboundBudget::with_limits(100, 0));
    let (hog, _hog_rx) = shared_lease(&shared);
    let (waiter, _waiter_rx) = shared_lease(&shared);
    let hog_budget = hog.budget_handle();
    let waiter_budget = waiter.budget_handle();
    let mut hog_credit = charge(&hog_budget, 100);
    assert!(!waiter_budget.may_charge(50));

    let ready = {
        let budget = Arc::clone(&waiter_budget);
        move || budget.may_charge(50)
    };
    let (thread, done) = spawn_waiter(&waiter_budget, Duration::from_secs(60), ready);
    std::thread::sleep(Duration::from_millis(50));
    hog_budget.shrink(&mut hog_credit, 40);
    let woke = done.recv_timeout(WAKE_DEADLINE);
    waiter_budget.mark_writer_dead();
    thread.join().unwrap_or_else(|_| panic!("waiter panicked"));
    assert!(woke.is_ok(), "a shrink must wake the waiter");
    assert_eq!(shared.pending(), 40);
    assert_eq!(hog_budget.pending(), (1, 40));

    let (second_waiter, _second_rx) = shared_lease(&shared);
    let second_budget = second_waiter.budget_handle();
    let held = charge(&second_budget, 50);
    assert!(!second_budget.may_charge(50), "40 + 50 + 50 exceeds 100");
    let ready = {
        let budget = Arc::clone(&second_budget);
        move || budget.may_charge(50)
    };
    let (thread, done) = spawn_waiter(&second_budget, Duration::from_secs(60), ready);
    std::thread::sleep(Duration::from_millis(50));
    drop(hog_credit);
    let woke = done.recv_timeout(WAKE_DEADLINE);
    second_budget.mark_writer_dead();
    thread.join().unwrap_or_else(|_| panic!("waiter panicked"));
    assert!(woke.is_ok(), "a credit drop must wake the waiter");
    drop(held);
    assert_eq!(shared.pending(), 0);
}

#[test]
fn credit_drop_exactly_once() {
    let shared = Arc::new(SharedOutboundBudget::with_limits(1_000, 0));
    let (bystander, _bystander_rx) = shared_lease(&shared);
    let bystander_credit = charge(&bystander.budget_handle(), 100);
    let (lease, _rx) = shared_lease(&shared);
    let budget = lease.budget_handle();

    let credit = charge(&budget, 40);
    assert_eq!(budget.pending(), (1, 40));
    assert_eq!(shared.pending(), 140);
    drop(credit);
    assert_eq!(budget.pending(), (0, 0));
    assert_eq!(shared.pending(), 100);

    let mut credit = charge(&budget, 60);
    budget.shrink(&mut credit, 20);
    assert_eq!(credit.bytes(), 20);
    assert_eq!(budget.pending(), (1, 20));
    assert_eq!(shared.pending(), 120);
    budget.shrink(&mut credit, 20);
    assert_eq!(
        shared.pending(),
        120,
        "shrinking to the same size is a no-op"
    );
    drop(credit);
    assert_eq!(budget.pending(), (0, 0));
    assert_eq!(shared.pending(), 100);

    drop(bystander_credit);
    assert_eq!(shared.pending(), 0);
}

#[test]
fn bulk_margin_keeps_control_flowing() {
    let reserve_bytes = 100;
    let shared = Arc::new(SharedOutboundBudget::with_limits(1_000, reserve_bytes));
    let (lease, _rx) = shared_lease_with_reserve(&shared, reserve_bytes);
    let budget = lease.budget_handle();

    let bulk: Vec<_> = (0..9).map(|_| reserve(&budget)).collect();
    assert_eq!(shared.pending(), 900);
    assert_eq!(budget.try_reserve_production().err(), Some(Refusal::Shared));
    assert!(!budget.may_reserve_production());

    let ping = crate::Message::Ping(9);
    assert!(lease.send(ping).is_ok());
    let control = charge(
        &budget,
        reserve_bytes - wire_len_of(&crate::Message::Ping(9)),
    );
    assert_eq!(shared.pending(), 1_000);
    assert_eq!(budget.try_charge(1).err(), Some(Refusal::Shared));
    drop((bulk, control));
}

#[test]
fn send_with_shrinks_the_reservation_to_the_wire_length() {
    let shared = Arc::new(SharedOutboundBudget::with_limits(10_000, 1_000));
    let (lease, rx) = shared_lease_with_reserve(&shared, 1_000);
    let credit = reserve(&lease.budget_handle());
    assert_eq!(shared.pending(), 1_000);

    let ping = crate::Message::Ping(1);
    let ping_len = wire_len_of(&ping);
    assert!(lease.send_with(credit, ping.clone()).is_ok());
    assert_eq!(shared.pending(), ping_len);
    assert_eq!(lease.budget_handle().pending(), (1, ping_len));

    let frame = rx
        .try_recv()
        .unwrap_or_else(|_| panic!("the frame was queued"));
    assert_eq!(frame.message(), &ping);
    assert_eq!(
        shared.pending(),
        ping_len,
        "the charge rides with the frame"
    );
    assert_eq!(frame.into_message(), ping);
    assert_eq!(shared.pending(), 0);
    assert_eq!(lease.budget_handle().pending(), (0, 0));
}

#[test]
fn send_with_fails_closed_and_releases_the_credit() {
    let shared = Arc::new(SharedOutboundBudget::with_limits(10_000, 0));

    let (small, _small_rx) = shared_lease(&shared);
    let credit = charge(&small.budget_handle(), 8);
    let ping = crate::Message::Ping(1);
    assert_eq!(
        small.send_with(credit, ping.clone()),
        Err(OutboundRefusal::Closed(ping))
    );
    assert!(
        small.is_cancelled(),
        "an outgrown reservation closes the lease"
    );
    assert_eq!(shared.pending(), 0);

    let (cancelled, _cancelled_rx) = shared_lease(&shared);
    let credit = charge(&cancelled.budget_handle(), 100);
    cancelled.cancel();
    let pong = crate::Message::Pong(2);
    assert_eq!(
        cancelled.send_with(credit, pong.clone()),
        Err(OutboundRefusal::Closed(pong))
    );
    assert_eq!(shared.pending(), 0);
    assert_eq!(cancelled.budget_handle().pending(), (0, 0));
}

#[test]
fn dead_writer_refuses_charges_and_reclaims_nothing() {
    let shared = Arc::new(SharedOutboundBudget::with_limits(1_000, 0));
    let (lease, rx) = shared_lease(&shared);
    let budget = lease.budget_handle();
    let ping_len = wire_len_of(&crate::Message::Ping(1));
    assert!(lease.send(crate::Message::Ping(1)).is_ok());
    assert!(lease.send(crate::Message::Ping(2)).is_ok());

    budget.mark_writer_dead();
    assert_eq!(shared.pending(), 2 * ping_len, "death reclaims nothing");
    assert_eq!(budget.pending(), (2, 2 * ping_len));
    assert_eq!(budget.try_charge(1).err(), Some(Refusal::Local));
    assert!(matches!(
        lease.send(crate::Message::Ping(3)),
        Err(OutboundRefusal::Closed(_))
    ));
    assert!(lease.is_cancelled());

    while let Ok(frame) = rx.try_recv() {
        drop(frame);
    }
    assert_eq!(shared.pending(), 0);
    assert_eq!(budget.pending(), (0, 0));
}

#[test]
fn shared_aggregate_caps_two_connections_without_touching_local_bounds() {
    let shared = Arc::new(SharedOutboundBudget::with_limits(100, 0));
    let (hog, _hog_rx) = shared_lease(&shared);
    let (other, _other_rx) = shared_lease(&shared);

    let hog_budget = hog.budget_handle();
    let first = charge(&hog_budget, 60);
    let second = charge(&hog_budget, 39);
    assert_eq!(shared.pending(), 99);
    assert!(hog_budget.may_charge(1));
    assert_eq!(hog_budget.pending(), (2, 99));

    let ping_len = wire_len_of(&crate::Message::Ping(1));
    let refused = crate::Message::Ping(1);
    assert_eq!(
        other.send(refused.clone()),
        Err(OutboundRefusal::Saturated(refused))
    );
    assert!(!other.is_cancelled());
    assert!(!hog.is_cancelled());
    assert_eq!(shared.pending(), 99);
    assert_eq!(other.budget_handle().pending(), (0, 0));

    drop(first);
    assert!(other.send(crate::Message::Ping(2)).is_ok());
    assert_eq!(shared.pending(), 39 + ping_len);

    let overflow = crate::Message::Ping(3);
    assert_eq!(
        other.send(overflow.clone()),
        Err(OutboundRefusal::Saturated(overflow))
    );
    assert!(!other.is_cancelled());
    drop(second);
}

#[test]
fn healthy_peer_progresses_beside_a_locally_saturated_peer() {
    let shared = Arc::new(SharedOutboundBudget::with_limits(1_000_000, 0));
    let (saturated_tx, _saturated_rx) = crossbeam_channel::unbounded();
    let saturated = PeerLease::new_with_budget(
        saturated_tx,
        false,
        OutboundBudget::with_block_reserve(1, 1_000_000, 0),
    )
    .with_shared_budget(&shared);
    let (healthy, _healthy_rx) = shared_lease(&shared);

    assert!(saturated.send(crate::Message::Ping(1)).is_ok());
    assert!(matches!(
        saturated.send(crate::Message::Ping(2)),
        Err(OutboundRefusal::Closed(_))
    ));
    assert!(saturated.is_cancelled());
    assert!(healthy.send(crate::Message::Ping(3)).is_ok());
    assert!(!healthy.is_cancelled());
}

#[test]
fn aggregate_waiter_resumes_on_another_connections_drain() {
    let shared = Arc::new(SharedOutboundBudget::with_limits(200, 0));
    let (hog, _hog_rx) = shared_lease(&shared);
    let (waiter, _waiter_rx) = shared_lease_with_reserve(&shared, 100);
    let waiter_budget = waiter.budget_handle();
    let hog_credit = charge(&hog.budget_handle(), 150);
    assert!(!waiter_budget.may_reserve_production());

    let ready = {
        let budget = Arc::clone(&waiter_budget);
        move || budget.may_reserve_production()
    };
    let (thread, done) = spawn_waiter(&waiter_budget, Duration::from_secs(60), ready);
    std::thread::sleep(Duration::from_millis(50));
    drop(hog_credit);
    let woke = done.recv_timeout(WAKE_DEADLINE);
    waiter_budget.mark_writer_dead();
    thread.join().unwrap_or_else(|_| panic!("waiter panicked"));
    assert!(
        woke.is_ok(),
        "another connection's drain must resume the waiter"
    );
    assert!(waiter_budget.may_reserve_production());
    assert_eq!(shared.pending(), 0);
}

#[test]
fn independent_aggregates_stay_independent() {
    let first = Arc::new(SharedOutboundBudget::with_limits(100, 0));
    let second = Arc::new(SharedOutboundBudget::with_limits(100, 0));
    let (a, _a_rx) = shared_lease(&first);
    let (b, _b_rx) = shared_lease(&second);

    let a_credit = charge(&a.budget_handle(), 100);
    assert_eq!(first.pending(), 100);
    let b_credit = charge(&b.budget_handle(), 100);
    assert_eq!(second.pending(), 100);
    drop(a_credit);
    assert_eq!(first.pending(), 0);
    assert_eq!(second.pending(), 100);
    drop(b_credit);
}

#[test]
fn release_replenishes_budget() {
    let (tx, rx) = crossbeam_channel::unbounded();
    let first = crate::Message::Ping(7);
    let ping_len = wire_len_of(&first);
    let lease = PeerLease::new_with_budget(
        tx,
        false,
        OutboundBudget::with_block_reserve(1, 10 * ping_len, 0),
    );

    assert!(lease.send(first).is_ok());
    assert_eq!(lease.budget_handle().pending(), (1, ping_len));

    assert!(matches!(
        lease.send(crate::Message::Ping(8)),
        Err(OutboundRefusal::Closed(_))
    ));
    assert!(lease.is_cancelled());
    assert_eq!(lease.budget_handle().pending(), (1, ping_len));

    let frame = rx
        .try_recv()
        .unwrap_or_else(|_| panic!("the first message was queued"));
    drop(frame);
    assert_eq!(lease.budget_handle().pending(), (0, 0));

    let (fresh_tx, _fresh_rx) = crossbeam_channel::unbounded();
    let fresh = PeerLease::new_with_budget(
        fresh_tx,
        false,
        OutboundBudget::with_block_reserve(1, 10 * ping_len, 0),
    );

    assert!(fresh.send(crate::Message::Ping(9)).is_ok());
}

#[test]
fn saturated_getdata_fourth_send_refuses_and_closes_lease() {
    let (tx, _undrained_rx) = crossbeam_channel::unbounded();
    let test_block = bitcoin_rs_primitives::Block::default();
    let block_wire_len = wire_len_of(&crate::Message::Block(
        bitcoin_rs_primitives::BlockPayload::from_local(test_block.clone()),
    ));
    let lease = PeerLease::new_with_budget(
        tx,
        false,
        OutboundBudget::with_block_reserve(100_000, 3 * block_wire_len, block_wire_len),
    );

    for _ in 0..3 {
        assert!(
            lease
                .send(crate::Message::Block(
                    bitcoin_rs_primitives::BlockPayload::from_local(test_block.clone()),
                ))
                .is_ok()
        );
    }
    assert!(matches!(
        lease.send(crate::Message::Block(
            bitcoin_rs_primitives::BlockPayload::from_local(test_block),
        )),
        Err(OutboundRefusal::Closed(_))
    ));

    assert!(lease.is_cancelled());
    assert_eq!(lease.budget_handle().pending(), (3, 3 * block_wire_len));

    let (independent_tx, _independent_rx) = crossbeam_channel::unbounded();
    let independent = PeerLease::new(independent_tx);
    assert!(independent.send(crate::Message::Ping(1)).is_ok());
}

fn spawn_waiter(
    budget: &Arc<OutboundBudget>,
    timeout: Duration,
    ready: impl Fn() -> bool + Send + 'static,
) -> (std::thread::JoinHandle<()>, Receiver<Instant>) {
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let waiter = Arc::clone(budget);
    let handle = std::thread::spawn(move || {
        waiter.wait_for(timeout, ready);
        let _ = done_tx.send(Instant::now());
    });
    (handle, done_rx)
}

fn saturated_budget() -> (Arc<OutboundBudget>, OutboundCredit) {
    let reserve_bytes = 100;
    let budget = standalone(10, 2 * reserve_bytes, reserve_bytes);
    let credit = charge(&budget, reserve_bytes + 1);
    assert!(!budget.may_reserve_production());
    (budget, credit)
}

fn production_ready(budget: &Arc<OutboundBudget>) -> impl Fn() -> bool + Send + use<> {
    let budget = Arc::clone(budget);
    move || budget.may_reserve_production()
}

const WAKE_DEADLINE: Duration = Duration::from_secs(10);

#[test]
fn release_wakes_a_waiter_long_before_its_timeout() {
    let (budget, credit) = saturated_budget();
    let (waiter, done) = spawn_waiter(&budget, Duration::from_secs(60), production_ready(&budget));

    std::thread::sleep(Duration::from_millis(50));
    drop(credit);

    let woke = done.recv_timeout(WAKE_DEADLINE);
    budget.mark_writer_dead();
    waiter.join().unwrap_or_else(|_| panic!("waiter panicked"));
    assert!(woke.is_ok(), "a release must wake the waiter");
    assert!(budget.may_reserve_production());
}

#[test]
fn writer_death_wakes_a_waiter_that_no_release_will_reach() {
    let (budget, _credit) = saturated_budget();
    let (waiter, done) = spawn_waiter(&budget, Duration::from_secs(60), production_ready(&budget));

    std::thread::sleep(Duration::from_millis(50));
    assert!(!budget.writer_dead());
    budget.mark_writer_dead();

    let woke = done.recv_timeout(WAKE_DEADLINE);
    waiter.join().unwrap_or_else(|_| panic!("waiter panicked"));
    assert!(woke.is_ok(), "writer death must wake the waiter");
    assert!(budget.writer_dead());
    assert!(
        !budget.may_reserve_production(),
        "death releases nothing; the queue stays saturated"
    );
}

#[test]
fn wait_returns_at_once_when_headroom_or_death_already_holds() {
    let open = standalone(10, 1_000, 100);
    let started = Instant::now();
    open.wait_for(Duration::from_secs(60), production_ready(&open));
    assert!(started.elapsed() < WAKE_DEADLINE);

    let (dead, _charged) = saturated_budget();
    dead.mark_writer_dead();
    let started = Instant::now();
    dead.wait_for(Duration::from_secs(60), production_ready(&dead));
    assert!(started.elapsed() < WAKE_DEADLINE);
}

#[test]
fn wait_times_out_without_a_wake() {
    let (budget, _credit) = saturated_budget();
    let timeout = Duration::from_millis(100);
    let started = Instant::now();

    budget.wait_for(timeout, production_ready(&budget));

    assert!(
        started.elapsed() >= timeout,
        "no wake, so the wait runs to its timeout"
    );
    assert!(!budget.may_reserve_production());
    assert!(!budget.writer_dead());
}

#[test]
fn a_release_that_leaves_the_queue_saturated_does_not_end_the_wait() {
    let reserve_bytes = 100;
    let budget = standalone(10, 2 * reserve_bytes, reserve_bytes);
    let mut credits: Vec<_> = (0..3).map(|_| charge(&budget, 90)).collect();
    assert!(!budget.may_reserve_production());
    let (waiter, done) = spawn_waiter(&budget, Duration::from_secs(60), production_ready(&budget));

    std::thread::sleep(Duration::from_millis(50));
    drop(credits.pop());
    let early = done.recv_timeout(Duration::from_millis(300));
    drop(credits.pop());
    let woke = done.recv_timeout(WAKE_DEADLINE);
    budget.mark_writer_dead();
    waiter.join().unwrap_or_else(|_| panic!("waiter panicked"));
    assert!(
        early.is_err(),
        "a still-saturated queue keeps the waiter parked"
    );
    assert!(woke.is_ok(), "the release that opens the gate wakes it");
}

fn wire_len_of(message: &crate::Message) -> usize {
    crate::wire::wire_len(message).unwrap_or_else(|_| panic!("test message must encode"))
}
