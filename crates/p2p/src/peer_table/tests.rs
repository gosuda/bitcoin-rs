use super::*;
use bitcoin_rs_primitives::PeerEndpoint;

#[test]
fn retiring_an_epoch_wakes_its_leases_without_cancelling_a_replacement() {
    let table = PeerTable::new();
    let old_epoch = Arc::new(AtomicBool::new(true));
    let new_epoch = Arc::new(AtomicBool::new(true));
    let address = crate::PeerEndpoint::new(crate::PeerAddress::I2p([7; 32]), 8333);
    let other = crate::PeerEndpoint::new(crate::PeerAddress::I2p([8; 32]), 8333);
    let old = lease().with_transport_alive(Some(Arc::clone(&old_epoch)));
    let remaining = lease().with_transport_alive(Some(Arc::clone(&old_epoch)));
    table.register(address, old.clone());
    table.register(other, remaining.clone());
    let successor = lease().with_transport_alive(Some(new_epoch));
    table.register(address, successor.clone());

    old_epoch.store(false, Ordering::Release);
    assert!(remaining.close_signal().try_recv().is_err());
    table.cancel_transport_epoch(&old_epoch);
    assert!(remaining.close_signal().try_recv().is_ok());
    assert!(!successor.is_cancelled());
    assert!(!table.remove_current(address, &old));
    assert!(
        table
            .lease(address)
            .is_some_and(|lease| lease.same_connection(&successor))
    );
    table.cancel_transport_epoch(&old_epoch);
    assert!(!successor.is_cancelled());
}

#[test]
fn anonymous_sources_keep_independent_leases_and_roundtrip_mempool_attribution() {
    let table = PeerTable::new();
    let (sender, _receiver) = crossbeam_channel::unbounded();
    let first = PeerLease::new_inbound(sender.clone());
    let second = PeerLease::new_inbound(sender);
    let first_remote = PeerRemote::AnonymousTor(first.connection_id());
    let second_remote = PeerRemote::AnonymousTor(second.connection_id());
    table.register(first_remote, first.clone());
    table.register(second_remote, second.clone());
    let source = first.source(None);
    let token = bitcoin_rs_mempool::PeerToken::from(source);
    assert_eq!(token.addr, None);
    assert_eq!(PeerSource::from(token), source);
    assert_ne!(
        token,
        bitcoin_rs_mempool::PeerToken::from(second.source(None))
    );
    assert_eq!(table.live_inbound_count(), 2);
    assert!(table.remove_current(first_remote, &first));
    assert!(!table.is_current(PeerSource::from(token)));
    assert!(table.is_current(second.source(None)));
    assert_eq!(table.live_inbound_count(), 1);
}

#[test]
fn revoked_overlay_epoch_cannot_replace_a_successor_during_late_admission() {
    let table = PeerTable::new();
    let address = PeerRemote::Endpoint(crate::PeerEndpoint::new(
        crate::PeerAddress::I2p([7; 32]),
        8333,
    ));
    let activity = crate::NetworkActivity::from_shared(Arc::new(AtomicBool::new(true)));
    let (sender, _receiver) = crossbeam_channel::unbounded();
    let successor = PeerLease::new(sender.clone());
    table.register(address, successor.clone());
    let dead = Arc::new(AtomicBool::new(false));
    let stale_outbound =
        PeerLease::new(sender.clone()).with_transport_alive(Some(Arc::clone(&dead)));
    assert!(
        table
            .try_register_outbound(address, stale_outbound, &activity)
            .is_none()
    );
    let stale_inbound = PeerLease::new_inbound(sender).with_transport_alive(Some(dead));
    assert!(
        table
            .try_register_inbound(address, stale_inbound, &[5, 7], 10, u64::MAX, &activity)
            .is_none()
    );
    assert!(!successor.is_cancelled());
    assert!(
        table
            .lease(address)
            .is_some_and(|lease| lease.same_connection(&successor))
    );
}
use crate::test_support::QueuedMessages as _;

fn addr(port: u16) -> PeerEndpoint {
    PeerEndpoint::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
}

fn lease() -> PeerLease {
    let (tx, _rx) = crossbeam_channel::unbounded();
    PeerLease::new(tx)
}

fn info(addr: PeerEndpoint, start_height: i32) -> PeerInfo {
    info_with_counters(
        addr,
        start_height,
        std::sync::Arc::new(crate::counters::PeerCounters::default()),
    )
}

fn info_with_counters(
    addr: PeerEndpoint,
    start_height: i32,
    counters: std::sync::Arc<crate::counters::PeerCounters>,
) -> PeerInfo {
    PeerInfo {
        addr: PeerRemote::Endpoint(addr),
        endpoint: Some(addr),
        network: addr.net(),
        version: 70016,
        wtxid_relay: false,
        relay_transactions: true,
        compact_block_relay: false,
        send_headers: false,
        services: 0,
        user_agent: String::new(),
        start_height,
        best_known_height: start_height,
        conn_time: 0,
        inbound: false,
        addr_bind: crate::TransportRemote::new(
            addr.socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        ),
        time_offset: 0,
        counters,
        transport: crate::TransportProtocol::V1,
    }
}

#[test]
fn register_replaces_and_cancels_predecessor_only() {
    let table = PeerTable::new();
    let first = lease();
    let second = lease();
    assert!(!table.register(addr(1), first.clone()));
    assert!(table.register(addr(1), second.clone()));
    assert!(first.is_cancelled());
    assert!(!second.is_cancelled());
    assert_eq!(table.len(), 1);
}

#[test]
fn anonymous_sessions_coexist_and_never_replace_known() {
    let table = PeerTable::new();
    let known = lease();
    assert!(!table.register(addr(1), known.clone()));
    let anon1 = inbound_lease();
    let anon2 = inbound_lease();
    assert!(!table.register_unidentified(anon1.clone()));
    assert!(!table.register_unidentified(anon2.clone()));
    assert_eq!(table.len(), 3);
    assert!(!table.register_unidentified(anon1.clone()));
    assert_eq!(table.len(), 3);
    assert!(!known.is_cancelled() && !anon1.is_cancelled() && !anon2.is_cancelled());
    let group = crate::endpoint::anonymous_netgroup(anon1.connection_id());
    assert_eq!(group.len(), 3);
    assert_eq!(group[0], 3);
    assert!(table.remove_unidentified(&anon1));
    assert_eq!(table.len(), 2);
}

#[test]
fn anonymous_inbound_reservation_is_capacity_only_and_carries_its_netgroup() {
    use std::hash::BuildHasher as _;
    let table = PeerTable::new();
    let activity = active_network();
    let known = inbound_lease();
    assert!(
        table
            .try_register_inbound(addr(1), known.clone(), &[], 1, 0, &activity)
            .is_some()
    );
    let refused = inbound_lease();
    assert!(
        table
            .try_register_inbound_unidentified(refused, 1, 0, &activity, None)
            .is_none()
    );
    assert!(!known.is_cancelled());
    assert_eq!(table.len(), 1);

    let anon1 = inbound_lease();
    let anon2 = inbound_lease();
    assert!(
        table
            .try_register_inbound_unidentified(anon1.clone(), 3, 0, &activity, None)
            .is_some()
    );
    assert!(
        table
            .try_register_inbound_unidentified(anon2.clone(), 3, 0, &activity, None)
            .is_some()
    );
    assert_eq!(table.len(), 3);
    assert!(!known.is_cancelled() && !anon1.is_cancelled() && !anon2.is_cancelled());

    let entries = table.entries.read();
    let mut keyed = Vec::new();
    for lease in [&anon1, &anon2] {
        let key = PeerRemote::AnonymousTor(lease.connection_id());
        let Some(candidate) = PeerTable::eviction_candidate(key, &entries[&key], 0) else {
            panic!("anonymous inbound is an eviction candidate");
        };
        assert_eq!(candidate.addr, key);
        assert_eq!(key.endpoint(), None);
        assert_eq!(
            candidate.keyed_netgroup,
            table
                .netgroup_key
                .hash_one(crate::endpoint::anonymous_netgroup(lease.connection_id()))
        );
        keyed.push(candidate.keyed_netgroup);
    }
    assert_ne!(keyed[0], keyed[1]);
}

#[test]
fn disconnect_onion_epoch_cancels_exact_generation_only_and_preserves_unrelated() {
    let table = PeerTable::new();
    let activity = active_network();

    let ip_peer = lease();
    assert!(!table.register(addr(1), ip_peer.clone()));

    let i2p_peer = lease();
    let i2p_endpoint = PeerEndpoint::I2p {
        hash: [7; 32],
        port: 7656,
    };
    assert!(!table.register(i2p_endpoint, i2p_peer.clone()));

    let tor_outbound = lease();
    let tor_endpoint = PeerEndpoint::TorV3 {
        key: [8; 32],
        port: 8333,
    };
    assert!(!table.register(tor_endpoint, tor_outbound.clone()));

    let anon_epoch1_a = inbound_lease();
    let anon_epoch1_b = inbound_lease();
    assert!(
        table
            .try_register_inbound_unidentified(anon_epoch1_a.clone(), 10, 0, &activity, Some(1),)
            .is_some()
    );
    assert!(
        table
            .try_register_inbound_unidentified(anon_epoch1_b.clone(), 10, 0, &activity, Some(1),)
            .is_some()
    );

    let anon_epoch2 = inbound_lease();
    assert!(
        table
            .try_register_inbound_unidentified(anon_epoch2.clone(), 10, 0, &activity, Some(2))
            .is_some()
    );

    let anon_none = inbound_lease();
    assert!(
        table
            .try_register_inbound_unidentified(anon_none.clone(), 10, 0, &activity, None)
            .is_some()
    );

    assert_eq!(table.len(), 7);

    let disconnected = table.disconnect_onion_epoch(1);
    assert_eq!(disconnected.len(), 2);
    assert!(disconnected.contains(&anon_epoch1_a.connection_id()));
    assert!(disconnected.contains(&anon_epoch1_b.connection_id()));

    assert!(anon_epoch1_a.is_cancelled());
    assert!(anon_epoch1_b.is_cancelled());

    assert!(!ip_peer.is_cancelled());
    assert!(!i2p_peer.is_cancelled());
    assert!(!tor_outbound.is_cancelled());
    assert!(!anon_epoch2.is_cancelled());
    assert!(!anon_none.is_cancelled());
    assert_eq!(table.len(), 5);

    let disconnected_repeat = table.disconnect_onion_epoch(1);
    assert_eq!(disconnected_repeat, []);
    assert_eq!(table.len(), 5);

    let disconnected_epoch2 = table.disconnect_onion_epoch(2);
    assert_eq!(disconnected_epoch2, vec![anon_epoch2.connection_id()]);
    assert!(anon_epoch2.is_cancelled());
    assert_eq!(table.len(), 4);

    assert!(!ip_peer.is_cancelled());
    assert!(!i2p_peer.is_cancelled());
    assert!(!tor_outbound.is_cancelled());
    assert!(!anon_none.is_cancelled());
}

fn active_network() -> crate::NetworkActivity {
    crate::NetworkActivity::from_shared(Arc::new(AtomicBool::new(true)))
}

fn inbound_lease() -> PeerLease {
    let (tx, _rx) = crossbeam_channel::unbounded();
    PeerLease::new_inbound(tx)
}

#[test]
fn network_disable_orders_before_or_after_inbound_and_outbound_admission() {
    for inbound in [false, true] {
        for disable_first in [false, true] {
            let table = PeerTable::new();
            let flag = Arc::new(AtomicBool::new(true));
            let activity = crate::NetworkActivity::from_shared(Arc::clone(&flag));
            let first = if inbound { inbound_lease() } else { lease() };
            if disable_first {
                table.set_network_active(&flag, false);
            }
            let registered = if inbound {
                table.try_register_inbound(addr(1), first.clone(), &[], 1, 0, &activity)
            } else {
                table.try_register_outbound(addr(1), first.clone(), &activity)
            };
            assert_eq!(registered.is_some(), !disable_first);
            if !disable_first {
                table.set_network_active(&flag, false);
            }
            assert!(!activity.is_active());
            assert_eq!(first.is_cancelled(), !disable_first);
            assert!(!table.is_current(first.source(Some(addr(1)))));
            assert_eq!(table.sessions().len(), usize::from(!disable_first));
            table.set_network_active(&flag, true);
            assert_eq!(
                first.is_cancelled(),
                !disable_first,
                "enable never revives a cancelled lease"
            );
            let fresh = if inbound { inbound_lease() } else { lease() };
            let registered = if inbound {
                table.try_register_inbound(addr(1), fresh.clone(), &[], 1, 0, &activity)
            } else {
                table.try_register_outbound(addr(1), fresh.clone(), &activity)
            };
            assert!(registered.is_some());
            assert!(table.is_current(fresh.source(Some(addr(1)))));
            assert!(!table.is_current(first.source(Some(addr(1)))));
        }
    }
}

#[test]
fn inactive_registration_never_mutates_or_returns_an_existing_lease() {
    for inbound in [false, true] {
        let table = PeerTable::new();
        let activity = crate::NetworkActivity::from_shared(Arc::new(AtomicBool::new(false)));
        let current = if inbound { inbound_lease() } else { lease() };
        assert!(!table.register(addr(1), current.clone()));
        let replacement = if inbound { inbound_lease() } else { lease() };
        for (address, candidate) in [
            (addr(1), current.clone()),
            (addr(1), replacement.clone()),
            (addr(2), replacement.clone()),
        ] {
            let registered = if inbound {
                table.try_register_inbound(address, candidate, &[], 0, 0, &activity)
            } else {
                table.try_register_outbound(address, candidate, &activity)
            };
            assert!(
                registered.is_none(),
                "activity precedes same-identity and capacity branches"
            );
            assert!(table.is_current(current.source(Some(addr(1)))));
            assert!(!current.is_cancelled());
            assert!(!replacement.is_cancelled());
            assert_eq!(table.sessions().len(), 1);
        }
    }
}

#[test]
fn try_register_inbound_refuses_at_zero_capacity() {
    let table = PeerTable::new();
    let lease = inbound_lease();
    assert!(
        table
            .try_register_inbound(addr(1), lease, &[], 0, 0, &active_network())
            .is_none(),
        "zero capacity refuses"
    );
    assert!(table.is_empty(), "a refusal changes no table state");
}

#[test]
fn try_register_inbound_admits_below_the_cap_only() {
    let table = PeerTable::new();
    let first = inbound_lease();
    assert!(
        table
            .try_register_inbound(addr(1), first, &[], 1, 0, &active_network())
            .is_some()
    );
    assert_eq!(table.live_inbound_count(), 1);
    let second = inbound_lease();
    assert!(
        table
            .try_register_inbound(addr(2), second.clone(), &[], 1, 0, &active_network())
            .is_none()
    );
    assert!(!second.is_cancelled(), "a refusal cancels nothing");
    assert_eq!(table.len(), 1);
}

#[test]
fn live_inbound_count_ignores_outbound_leases() {
    let table = PeerTable::new();
    table.register(addr(1), lease());
    assert_eq!(table.live_inbound_count(), 0);
    assert!(
        table
            .try_register_inbound(addr(2), inbound_lease(), &[], 1, 0, &active_network())
            .is_some()
    );
    assert_eq!(table.live_inbound_count(), 1);
}

#[test]
fn removal_releases_inbound_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let table = PeerTable::new();
    let registered = table
        .try_register_inbound(addr(1), inbound_lease(), &[], 1, 0, &active_network())
        .ok_or("capacity must admit the first inbound lease")?;
    assert!(table.remove_current(addr(1), &registered));
    assert_eq!(table.live_inbound_count(), 0);
    assert!(
        table
            .try_register_inbound(addr(2), inbound_lease(), &[], 1, 0, &active_network())
            .is_some()
    );
    Ok(())
}

#[test]
fn inbound_replacement_at_capacity_keeps_the_count_and_cancels_the_predecessor() {
    let table = PeerTable::new();
    let first = inbound_lease();
    assert!(
        table
            .try_register_inbound(addr(1), first.clone(), &[], 1, 0, &active_network())
            .is_some(),
        "capacity must admit the first inbound lease"
    );
    assert!(
        table
            .try_register_inbound(addr(1), inbound_lease(), &[], 1, 0, &active_network())
            .is_some(),
        "a same-address replacement never grows the count and is admitted at capacity"
    );
    assert!(first.is_cancelled());
    assert_eq!(table.live_inbound_count(), 1);
}

#[test]
fn inbound_replacement_over_a_cancelled_predecessor_faces_the_cap() {
    let table = PeerTable::new();
    let displaced = inbound_lease();
    assert!(
        table
            .try_register_inbound(addr(1), displaced.clone(), &[], 1, 0, &active_network())
            .is_some(),
        "capacity must admit the first inbound lease"
    );
    displaced.cancel();
    assert_eq!(
        table.live_inbound_count(),
        0,
        "a cancelled lease stops counting the moment it is cancelled"
    );
    assert!(
        table
            .try_register_inbound(addr(2), inbound_lease(), &[], 1, 0, &active_network())
            .is_some(),
        "the slot the cancellation freed goes to the next address"
    );
    assert!(
        table
            .try_register_inbound(addr(1), inbound_lease(), &[], 1, 0, &active_network())
            .is_none(),
        "replacing a cancelled inbound lease adds a live entry, so it must face the cap"
    );
    assert_eq!(
        table.live_inbound_count(),
        1,
        "the refusal must not admit a second live inbound lease"
    );
}

fn flooder(port: u16) -> PeerEndpoint {
    PeerEndpoint::Ip(std::net::SocketAddr::from(([1, 2, 3, 4], port)))
}

fn newcomer() -> PeerEndpoint {
    PeerEndpoint::Ip(std::net::SocketAddr::from(([5, 6, 7, 8], 8333)))
}

fn netgroup(addr: PeerEndpoint) -> Vec<u8> {
    crate::netgroup::NetGroups::default().group(addr.address())
}

fn offer(
    table: &PeerTable,
    addr: PeerEndpoint,
    lease: PeerLease,
    max_inbound: usize,
) -> Option<PeerLease> {
    table.try_register_inbound(
        addr,
        lease,
        &netgroup(addr),
        max_inbound,
        0,
        &active_network(),
    )
}

#[expect(clippy::expect_used)]
fn flood(table: &PeerTable, max_inbound: u16, no_ban: bool) -> Vec<PeerLease> {
    let now = std::time::Instant::now();
    (1..=max_inbound)
        .map(|port| {
            let mut lease = inbound_lease().with_no_ban(no_ban);
            lease.backdate_for_test(
                now.checked_sub(std::time::Duration::from_millis(u64::from(
                    max_inbound - port + 1,
                )))
                .expect("the monotonic clock has run longer than the flood"),
            );
            offer(table, flooder(port), lease, usize::from(max_inbound)).expect("below capacity")
        })
        .collect()
}

fn cancelled(leases: &[PeerLease]) -> Vec<usize> {
    (0..leases.len())
        .filter(|index| leases[*index].is_cancelled())
        .collect()
}

#[test]
fn one_host_filling_every_inbound_slot_gives_way_to_another_netgroup() {
    let table = PeerTable::new();
    let flooded = flood(&table, 20, false);
    let honest = inbound_lease();
    assert!(
        offer(&table, newcomer(), honest.clone(), 20).is_some(),
        "a full table must evict rather than refuse a newcomer"
    );
    assert_eq!(table.live_inbound_count(), 20);
    assert_eq!(cancelled(&flooded).len(), 1);
    assert!(offer(&table, flooder(999), inbound_lease(), 20).is_some());
    assert!(!honest.is_cancelled());
    assert_eq!(cancelled(&flooded).len(), 2);
    assert_eq!(table.live_inbound_count(), 20);
}

#[test]
fn noban_inbound_connections_are_never_evicted() {
    let table = PeerTable::new();
    let flooded = flood(&table, 20, true);
    assert!(offer(&table, newcomer(), inbound_lease(), 20).is_none());
    assert_eq!(cancelled(&flooded), Vec::<usize>::new());
    assert_eq!(table.live_inbound_count(), 20);
}

#[test]
fn a_full_table_refuses_an_inbound_newcomer_at_a_live_outbound_address() {
    let table = PeerTable::new();
    let outbound = lease();
    table.register(newcomer(), outbound.clone());
    let flooded = flood(&table, 20, false);
    assert!(
        offer(&table, newcomer(), inbound_lease(), 20).is_none(),
        "evicting would drop two connections, the outbound one included, for one"
    );
    assert!(!outbound.is_cancelled());
    assert_eq!(cancelled(&flooded), Vec::<usize>::new());
}

#[test]
fn useful_transactions_and_blocks_protect_inbound_connections() {
    let table = PeerTable::new();
    let flooded = flood(&table, 13, false);
    assert!(!table.note_useful_transaction(inbound_lease().source(Some(flooder(12)))));
    assert!(table.note_useful_transaction(flooded[11].source(Some(flooder(12)))));
    assert!(table.note_useful_block(flooded[12].source(Some(flooder(13)))));
    assert!(offer(&table, newcomer(), inbound_lease(), 13).is_some());
    assert_eq!(cancelled(&flooded), [10]);
}

#[test]
fn re_registering_current_connection_is_noop_and_keeps_info() {
    let table = PeerTable::new();
    let current = lease();
    table.register(addr(1), current.clone());
    assert!(table.publish_info(addr(1), &current, info(addr(1), 7)));
    assert!(!table.register(addr(1), current.clone()));
    assert!(!current.is_cancelled());
    assert_eq!(table.infos().len(), 1);
}

#[test]
fn publish_info_rejects_stale_connection() {
    let table = PeerTable::new();
    let stale = lease();
    let current = lease();
    table.register(addr(1), stale.clone());
    table.register(addr(1), current.clone());
    assert!(!table.publish_info(addr(1), &stale, info(addr(1), 1)));
    assert_eq!(table.infos(), []);
    assert!(table.publish_info(addr(1), &current, info(addr(1), 2)));
    assert_eq!(table.infos()[0].start_height, 2);
}

#[test]
fn stale_handle_cannot_remove_successor() {
    let table = PeerTable::new();
    let stale = lease();
    let current = lease();
    table.register(addr(1), stale.clone());
    table.register(addr(1), current.clone());
    assert!(!table.remove_current(addr(1), &stale));
    assert!(!table.disconnect_source(stale.source(Some(addr(1)))));
    assert!(table.is_connected(addr(1)));
    assert!(!current.is_cancelled());
    assert!(table.disconnect_source(current.source(Some(addr(1)))));
    assert!(current.is_cancelled());
    assert!(table.is_empty());
}

#[test]
fn disconnect_removes_lease_and_info_together() {
    let table = PeerTable::new();
    let current = lease();
    table.register(addr(1), current.clone());
    table.publish_info(addr(1), &current, info(addr(1), 1));
    assert!(table.disconnect(addr(1)));
    assert!(!table.disconnect(addr(1)));
    assert!(current.is_cancelled());
    assert_eq!(table.infos(), []);
    assert!(table.lease(addr(1)).is_none());
}

#[test]
fn disconnect_connection_does_not_remove_replacement() {
    let table = PeerTable::new();
    let stale = lease();
    let replacement = lease();
    table.register(addr(1), stale.clone());
    let stale_id = stale.connection_id();
    table.register(addr(1), replacement.clone());
    assert!(!table.disconnect_connection(addr(1), stale_id));
    assert!(table.is_connected(addr(1)));
    assert!(!replacement.is_cancelled());
}

fn register_ready(table: &PeerTable, endpoint: PeerEndpoint, lease: &PeerLease) {
    table.register(endpoint, lease.clone());
    assert!(table.publish_info(endpoint, lease, info(endpoint, 0)));
}

#[test]
fn disconnect_ready_node_id_selects_the_named_connection_across_a_replacement() {
    let table = PeerTable::new();
    let selected = lease();
    let replacement = lease();
    let selected_id = selected.node_id();
    let replacement_id = replacement.node_id();
    register_ready(&table, addr(1), &selected);
    register_ready(&table, addr(1), &replacement);

    assert!(
        !table.disconnect_ready_node_id(selected_id),
        "the selected connection is gone; its identity must not resolve to the successor"
    );
    assert!(table.is_connected(addr(1)));
    assert!(!replacement.is_cancelled());
    assert_eq!(table.len(), 1);

    assert!(table.disconnect_ready_node_id(replacement_id));
    assert!(replacement.is_cancelled());
    assert!(table.is_empty());
}

#[test]
fn disconnect_ready_node_id_at_requires_the_address_and_the_identity() {
    let table = PeerTable::new();
    let selected = lease();
    let replacement = lease();
    let selected_id = selected.node_id();
    let replacement_id = replacement.node_id();
    register_ready(&table, addr(1), &selected);
    register_ready(&table, addr(1), &replacement);

    assert!(!table.disconnect_ready_node_id_at(addr(1), selected_id));
    assert!(!table.disconnect_ready_node_id_at(addr(2), replacement_id));
    assert!(!replacement.is_cancelled());
    assert_eq!(table.len(), 1);

    assert!(table.disconnect_ready_node_id_at(addr(1), replacement_id));
    assert!(replacement.is_cancelled());
    assert!(table.is_empty());
}

#[test]
fn disconnect_by_address_hits_the_live_connection_not_the_named_one() {
    let table = PeerTable::new();
    let selected = lease();
    let replacement = lease();
    table.register(addr(1), selected);
    table.register(addr(1), replacement.clone());

    assert!(table.disconnect(addr(1)));
    assert!(replacement.is_cancelled());
    assert!(table.is_empty());
}

#[test]
fn disconnect_ready_family_refuses_a_session_that_is_still_handshaking() {
    let table = PeerTable::new();
    let pending = lease();
    let node_id = pending.node_id();
    table.register(addr(1), pending.clone());

    assert!(!table.disconnect_ready(addr(1)));
    assert!(!table.disconnect_ready_node_id(node_id));
    assert!(!table.disconnect_ready_node_id_at(addr(1), node_id));
    assert!(!pending.is_cancelled());
    assert_eq!(table.len(), 1);

    assert!(table.publish_info(addr(1), &pending, info(addr(1), 0)));
    assert!(table.disconnect_ready(addr(1)));
    assert!(pending.is_cancelled());
    assert!(table.is_empty());
}

#[test]
fn disconnect_ready_leaves_an_unpublished_replacement_alone() {
    let table = PeerTable::new();
    let first = lease();
    let replacement = lease();
    register_ready(&table, addr(1), &first);
    table.register(addr(1), replacement.clone());

    assert!(!table.disconnect_ready(addr(1)));
    assert!(!replacement.is_cancelled());
    assert_eq!(table.len(), 1);
}

#[test]
fn disconnect_ready_node_id_reaches_anonymous_sessions_and_spares_neighbours() {
    let table = PeerTable::new();
    let known = lease();
    register_ready(&table, addr(1), &known);
    let anon1 = inbound_lease();
    let anon2 = inbound_lease();
    assert!(!table.register_unidentified(anon1.clone()));
    assert!(!table.register_unidentified(anon2.clone()));
    let anonymous = PeerInfo {
        endpoint: None,
        ..info(addr(9), 0)
    };
    assert!(table.publish_info_unidentified(&anon1, anonymous.clone()));
    assert!(table.publish_info_unidentified(&anon2, anonymous));

    assert!(table.disconnect_ready_node_id(anon1.node_id()));
    assert!(anon1.is_cancelled());
    assert!(
        !anon2.is_cancelled(),
        "an unrelated anonymous session stays"
    );
    assert!(!known.is_cancelled(), "an identified session stays");
    assert_eq!(table.len(), 2);
}

#[test]
fn disconnect_ready_node_id_reports_absence_without_mutation() {
    let table = PeerTable::new();
    let live = lease();
    register_ready(&table, addr(1), &live);
    let unknown = live.node_id().wrapping_add(1);

    assert!(!table.disconnect_ready_node_id(unknown));
    assert!(!live.is_cancelled());
    assert_eq!(table.len(), 1);
}

#[test]
fn cancel_all_keeps_entries_for_owner_removal() {
    let table = PeerTable::new();
    let a = lease();
    let b = lease();
    table.register(addr(1), a.clone());
    table.register(addr(2), b.clone());
    table.cancel_all();
    assert!(a.is_cancelled() && b.is_cancelled());
    assert_eq!(table.len(), 2);
    assert!(table.remove_current(addr(1), &a));
    assert!(table.remove_current(addr(2), &b));
    assert!(table.is_empty());
}

#[test]
fn infos_and_sessions_follow_connection_order() {
    let table = PeerTable::new();
    let leases: Vec<PeerLease> = (0..5).map(|_| lease()).collect();
    for (port, lease) in (10..15).rev().zip(leases.iter()) {
        table.register(addr(port), lease.clone());
        table.publish_info(addr(port), lease, info(addr(port), i32::from(port)));
    }
    let ports: Vec<u16> = table
        .infos()
        .iter()
        .map(|info| {
            info.addr
                .endpoint()
                .unwrap_or_else(|| panic!("known destination"))
                .port()
        })
        .collect();
    assert_eq!(ports, vec![14, 13, 12, 11, 10]);
    let session_ports: Vec<u16> = table
        .sessions()
        .iter()
        .map(|s| {
            s.addr
                .endpoint()
                .unwrap_or_else(|| panic!("known destination"))
                .port()
        })
        .collect();
    assert_eq!(session_ports, ports);
}

#[test]
fn with_current_rejects_stale_source_and_holds_live_identity() {
    let table = PeerTable::new();
    let (stale_tx, stale_rx) = crossbeam_channel::unbounded();
    let (current_tx, current_rx) = crossbeam_channel::unbounded();
    let stale = PeerLease::new(stale_tx);
    let current = PeerLease::new(current_tx);
    table.register(addr(1), stale.clone());
    let stale_source = stale.source(Some(addr(1)));
    table.register(addr(1), current.clone());
    let current_source = current.source(Some(addr(1)));

    let mut called = false;
    assert!(!table.with_current(stale_source, || called = true));
    assert!(!called);
    assert!(table.with_current(current_source, || {
        assert!(table.entries.try_write().is_none());
        assert!(current.send(crate::Message::Ping(1)).is_ok());
        called = true;
    }));
    assert!(called);
    assert!(matches!(
        current_rx.try_message(),
        Ok(crate::Message::Ping(1))
    ));
    assert!(table.send(stale_source, crate::Message::Ping(1)).is_err());
    assert!(stale_rx.try_recv().is_err());
    assert!(table.send(current_source, crate::Message::Ping(2)).is_ok());
    assert!(matches!(
        current_rx.try_message(),
        Ok(crate::Message::Ping(2))
    ));

    current.cancel();
    assert!(table.send(current_source, crate::Message::Ping(3)).is_err());
    assert!(current_rx.try_recv().is_err());
    assert!(!table.with_current(current_source, || panic!("cancelled source")));
}

#[test]
fn disconnect_matching_reports_affected_addresses() {
    let table = PeerTable::new();
    let a = lease();
    let b = lease();
    table.register(addr(1), a.clone());
    table.register(addr(2), b.clone());
    let removed = table.disconnect_matching(|addr, _| {
        addr.endpoint()
            .unwrap_or_else(|| panic!("known destination"))
            .port()
            == 2
    });
    assert_eq!(removed, vec![crate::PeerRemote::Endpoint(addr(2))]);
    assert!(b.is_cancelled());
    assert!(!a.is_cancelled());
    assert_eq!(table.len(), 1);
}

#[test]
fn note_announced_height_credits_only_the_delivering_connection() {
    let table = PeerTable::new();
    let (stale_tx, _stale_rx) = crossbeam_channel::unbounded();
    let stale = PeerLease::new(stale_tx);
    table.register(addr(1), stale.clone());
    let stale_source = stale.source(Some(addr(1)));

    let (current_tx, _current_rx) = crossbeam_channel::unbounded();
    let current = PeerLease::new(current_tx);
    table.register(addr(1), current.clone());
    let current_source = current.source(Some(addr(1)));
    assert!(table.publish_info(addr(1), &current, info(addr(1), 10)));

    assert!(!table.note_announced_height(stale_source, 42));
    assert_eq!(table.infos()[0].best_known_height, 10);

    assert!(table.note_announced_height(current_source, 42));
    assert_eq!(table.infos()[0].best_known_height, 42);
}

#[test]
fn note_headers_progress_lifts_the_cap_only_on_verified_advance() {
    let table = PeerTable::new();
    let current = lease();
    table.register(addr(1), current.clone());
    let source = current.source(Some(addr(1)));
    assert!(table.publish_info(addr(1), &current, info(addr(1), 100)));

    assert!(table.note_headers_horizon(source, 5));

    assert!(table.note_headers_progress(source, 5));
    let sessions = table.sessions();
    assert_eq!(sessions[0].headers_horizon, Some(5));

    assert!(table.note_headers_progress(source, 12));
    let sessions = table.sessions();
    assert_eq!(sessions[0].headers_horizon, None);
    assert_eq!(
        sessions[0].info.as_ref().map(|info| info.best_known_height),
        Some(100)
    );
}

#[test]
fn note_announced_height_raises_monotonically_and_reports_actual_updates() {
    let table = PeerTable::new();
    let current = lease();
    table.register(addr(1), current.clone());
    let source = current.source(Some(addr(1)));
    assert!(table.publish_info(addr(1), &current, info(addr(1), 10)));

    assert!(!table.note_announced_height(source, 10));
    assert_eq!(table.infos()[0].best_known_height, 10);

    assert!(!table.note_announced_height(source, 9));
    assert_eq!(table.infos()[0].best_known_height, 10);

    assert!(table.note_announced_height(source, 12));
    assert_eq!(table.infos()[0].best_known_height, 12);

    let demonstrated_tip = Hash256::from_le_bytes(&[7_u8; 32]);
    assert!(table.note_announced_tip(source, demonstrated_tip, Some(13)));
    assert_eq!(table.infos()[0].best_known_height, 13);
    assert_eq!(
        table.sessions()[0].demonstrated_tips,
        vec![demonstrated_tip]
    );

    let other = lease();
    let other_source = other.source(Some(addr(2)));
    assert!(!table.note_announced_height(other_source, 99));

    table.register(addr(3), lease());
    let Some(unpublished) = table.lease(addr(3)) else {
        return;
    };
    let unpublished_source = unpublished.source(Some(addr(3)));
    assert!(!table.note_announced_height(unpublished_source, 50));
}

#[test]
fn note_compact_relay_credits_only_the_delivering_connection() {
    let table = PeerTable::new();
    let (stale_tx, _stale_rx) = crossbeam_channel::unbounded();
    let stale = PeerLease::new(stale_tx);
    table.register(addr(1), stale.clone());
    let stale_source = stale.source(Some(addr(1)));

    let (current_tx, _current_rx) = crossbeam_channel::unbounded();
    let current = PeerLease::new(current_tx);
    table.register(addr(1), current.clone());
    let current_source = current.source(Some(addr(1)));
    assert!(table.publish_info(addr(1), &current, info(addr(1), 10)));

    assert!(!table.note_compact_relay(stale_source));
    assert!(!table.compact_relay_of(addr(1)));

    assert!(table.note_compact_relay(current_source));
    assert!(table.compact_relay_of(addr(1)));

    assert!(!table.compact_relay_of(addr(2)));
    table.register(addr(3), lease());
    assert!(!table.compact_relay_of(addr(3)));
}

#[test]
fn compact_announcement_snapshots_only_negotiated_versions() {
    let table = PeerTable::new();
    let current = lease();
    table.register(addr(1), current.clone());
    assert!(table.publish_info(addr(1), &current, info(addr(1), 10)));
    let source = current.source(Some(addr(1)));
    let mut negotiation = CompactBlockNegotiation::default();

    negotiation.record_remote_preference(&bitcoin::p2p::message_compact_blocks::SendCmpct {
        send_compact: true,
        version: 7,
    });
    assert!(!table.note_compact_announcement(source, &negotiation));
    assert!(!table.sessions()[0].bip152_hb_from);
    assert_eq!(
        table.announcement_state(source),
        Some(PeerAnnouncementState::default())
    );

    negotiation.record_remote_preference(&bitcoin::p2p::message_compact_blocks::SendCmpct {
        send_compact: true,
        version: crate::peer::COMPACT_BLOCK_VERSION,
    });
    assert!(table.note_compact_announcement(source, &negotiation));
    assert!(table.sessions()[0].bip152_hb_from);

    negotiation.record_remote_preference(&bitcoin::p2p::message_compact_blocks::SendCmpct {
        send_compact: false,
        version: 1,
    });
    assert!(table.note_compact_announcement(source, &negotiation));
    assert_eq!(
        table.announcement_state(source),
        Some(PeerAnnouncementState {
            compact_high_bandwidth: Some(true),
            compact_version: Some(crate::peer::COMPACT_BLOCK_VERSION),
            ..PeerAnnouncementState::default()
        })
    );
    assert!(table.sessions()[0].bip152_hb_from);
}

#[test]
fn traffic_totals_stay_monotonic_across_removals() {
    use std::io::{Cursor, Write as _};

    fn counted(
        counters: &Arc<crate::counters::PeerCounters>,
    ) -> crate::counters::CountingStream<Cursor<Vec<u8>>> {
        crate::counters::CountingStream::new(Cursor::new(Vec::new()), Arc::clone(counters))
    }

    let table = PeerTable::new();
    assert_eq!(table.traffic_totals(), (0, 0));

    let first = lease();
    let counters_first = Arc::new(crate::counters::PeerCounters::default());
    table.register(addr(1), first.clone());
    table.publish_info(
        addr(1),
        &first,
        info_with_counters(addr(1), 1, counters_first.clone()),
    );
    assert!(counted(&counters_first).write_all(&[0_u8; 10]).is_ok());
    assert_eq!(table.traffic_totals(), (0, 10));

    let second = lease();
    assert!(table.register(addr(1), second.clone()));
    assert_eq!(table.traffic_totals(), (0, 10));

    let counters_second = Arc::new(crate::counters::PeerCounters::default());
    table.publish_info(
        addr(1),
        &second,
        info_with_counters(addr(1), 2, counters_second.clone()),
    );
    let mut stream_second = counted(&counters_second);
    assert!(stream_second.write_all(&[0_u8; 20]).is_ok());
    assert_eq!(table.traffic_totals(), (0, 30));
    assert!(table.disconnect(addr(1)));
    assert!(stream_second.write_all(&[0_u8; 5]).is_ok());
    assert_eq!(table.traffic_totals(), (0, 35));

    let third = lease();
    let counters_third = Arc::new(crate::counters::PeerCounters::default());
    table.register(addr(2), third.clone());
    table.publish_info(
        addr(2),
        &third,
        info_with_counters(addr(2), 3, counters_third.clone()),
    );
    assert!(counted(&counters_third).write_all(&[0_u8; 7]).is_ok());
    let removed = table.disconnect_matching(|addr, _| {
        addr.endpoint()
            .unwrap_or_else(|| panic!("known destination"))
            .port()
            == 2
    });
    assert_eq!(removed, vec![crate::PeerRemote::Endpoint(addr(2))]);
    assert_eq!(table.traffic_totals(), (0, 42));

    drop(stream_second);
    drop(counters_first);
    drop(counters_second);
    drop(counters_third);
    let fourth = lease();
    table.register(addr(3), fourth);
    assert!(table.disconnect(addr(3)));
    assert_eq!(table.entries.read().retired, []);
    assert_eq!(table.traffic_totals(), (0, 42));
}

#[test]
fn outbound_role_counts_split_by_relay_role() {
    let table = PeerTable::new();
    let (full_tx, _full_rx) = crossbeam_channel::unbounded();
    table.register(addr(1), PeerLease::new(full_tx));
    let (second_full_tx, _second_full_rx) = crossbeam_channel::unbounded();
    table.register(addr(2), PeerLease::new(second_full_tx));
    let (block_tx, _block_rx) = crossbeam_channel::unbounded();
    table.register(addr(3), PeerLease::new_block_relay(block_tx));
    let (inbound_tx, _inbound_rx) = crossbeam_channel::unbounded();
    table.register(addr(4), PeerLease::new_inbound(inbound_tx));
    let (dead_tx, _dead_rx) = crossbeam_channel::unbounded();
    let cancelled = PeerLease::new(dead_tx);
    cancelled.cancel();
    table.register(addr(5), cancelled);

    let (manual_tx, _manual_rx) = crossbeam_channel::unbounded();
    table.register(
        addr(6),
        PeerLease::new_manual(manual_tx, crate::peer_info::PeerRole::FullRelay),
    );

    assert_eq!(
        table.outbound_role_counts(),
        (2, 1),
        "two automatic full-relay and one automatic block-relay connection"
    );
}

#[test]
fn overlay_identity_remote_never_uses_proxy_ip() {
    use crate::PeerEndpoint;
    use crate::connection::PeerRemote;
    let loopback = PeerEndpoint::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
    let anon_id = crate::ConnectionId::for_test_raw(123);
    let anon = PeerRemote::AnonymousTor(anon_id);
    assert_eq!(
        PeerRemote::from_endpoint(None, anon_id),
        PeerRemote::AnonymousTor(anon_id),
        "None endpoint is anonymous, never the forwarder socket"
    );
    assert_eq!(anon.endpoint(), None);
    assert_ne!(
        anon,
        PeerRemote::Endpoint(loopback),
        "no proxy IP enters session identity"
    );
    let tor = PeerEndpoint::TorV3 {
        key: [7u8; 32],
        port: 8333,
    };
    assert_eq!(
        PeerRemote::from_endpoint(Some(tor), anon_id),
        PeerRemote::Endpoint(tor),
        "identified Tor keeps its typed endpoint"
    );
    let i2p = PeerEndpoint::I2p {
        hash: [9u8; 32],
        port: 7656,
    };
    assert_eq!(
        PeerRemote::from_endpoint(Some(i2p), anon_id),
        PeerRemote::Endpoint(i2p),
        "SAM-attested I2P keeps its typed endpoint"
    );
}
