use super::*;
use crate::PeerSource;
use bitcoin_rs_primitives::PeerEndpoint;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};

#[test]
fn feeler_poisson_delay_matches_actual_core_uniform_vectors() {
    let data: sonic_rs::Value =
        sonic_rs::from_str(include_str!("../../tests/data/core-poisson-v31.1.json"))
            .expect("actual Core sampling fixture");
    for row in data["rows"].as_array().expect("rows") {
        assert_eq!(
            feeler_delay(row["uniform"].as_u64().expect("uniform")).as_micros(),
            u128::from(row["delay_us"].as_u64().expect("microseconds")),
            "{row}"
        );
    }
}

fn idle_ready() -> Arc<dyn Fn(PeerSource) + Send + Sync> {
    Arc::new(|_source: PeerSource| {})
}

#[test]
fn relay_feature_switches_default_off_and_reach_connections_independently() {
    let (headers, _) = crossbeam_channel::bounded(1);
    let (blocks, _) = crossbeam_channel::bounded(1);
    let mut shared = crate::listener::ConnectionShared::new(
        Arc::new(crate::PeerTable::new()),
        BannedReader::fixture_empty(),
        Arc::new(crate::NetworkActivity::from_shared(Arc::new(
            AtomicBool::new(true),
        ))),
        Arc::new(AtomicBool::new(false)),
        None,
        Magic::REGTEST,
        headers,
        blocks,
        None,
        None,
        crate::listener::ListenerExtras::default(),
    );
    P2pServiceConfig::default().apply_to(&mut shared);
    assert_eq!(shared.relay_offers, crate::RelayOffers::default());

    for offers in [
        crate::RelayOffers {
            package_relay: true,
            ..crate::RelayOffers::default()
        },
        crate::RelayOffers {
            stale_tip_relay: true,
            ..crate::RelayOffers::default()
        },
        crate::RelayOffers {
            stale_tip_relay: true,
            stale_tip_prefers_blocks: true,
            ..crate::RelayOffers::default()
        },
        crate::RelayOffers::default(),
    ] {
        P2pServiceConfig {
            relay_offers: offers,
            ..P2pServiceConfig::default()
        }
        .apply_to(&mut shared);
        assert_eq!(shared.relay_offers, offers);
    }
}

#[test]
fn start_fails_when_listener_cannot_bind() {
    let occupied = TcpListener::bind(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )
    .expect("occupy port");
    let addr = occupied.local_addr().expect("local_addr");
    let service = P2pService::new(
        P2pServiceConfig {
            listen_addrs: vec![addr],
            ..P2pServiceConfig::default()
        },
        Arc::new(AtomicBool::new(false)),
    );
    let error = service
        .start(
            None,
            None,
            &idle_ready(),
            crate::listener::ListenerExtras::default(),
        )
        .expect_err("occupied listen addr must fail start");
    assert!(
        matches!(error, P2pServiceError::Listener(ListenerError::Bind { .. })),
        "start must surface the bind failure, got {error:?}"
    );
    service.shutdown();
    service
        .join()
        .expect("failed start must leave the service joinable");
    drop(occupied);
}

#[test]
fn independent_services_own_independent_aggregate_budgets() {
    let first = P2pService::new(
        P2pServiceConfig::default(),
        Arc::new(AtomicBool::new(false)),
    );
    let second = P2pService::new(
        P2pServiceConfig::default(),
        Arc::new(AtomicBool::new(false)),
    );
    let a = first.shared_outbound_budget();
    let b = second.shared_outbound_budget();
    assert!(!Arc::ptr_eq(&a, &b), "services must not share an aggregate");
    let (queue, _receiver) = crate::test_support::message_channel();
    let lease = crate::PeerLease::new(queue).with_shared_budget(&a);
    assert!(lease.send(crate::Message::Ping(1)).is_ok());
    assert!(a.pending() > 0, "the send counts against its service");
    assert_eq!(b.pending(), 0, "the other service is unaffected");
}

#[test]
fn start_and_join_succeed_without_listeners() {
    let service = P2pService::new(
        P2pServiceConfig::default(),
        Arc::new(AtomicBool::new(false)),
    );
    service
        .start(
            None,
            None,
            &idle_ready(),
            crate::listener::ListenerExtras::default(),
        )
        .expect("empty listen set starts");
    service.shutdown();
    service.join().expect("clean join");
}

#[test]
fn overlay_workers_are_retained_for_join_and_rollback() {
    let dir = tempfile::tempdir().expect("identity dir");
    let mut config = P2pServiceConfig::default();
    config.overlay.onion_proxy = Some(SocketAddr::from(([127, 0, 0, 1], 19051)));
    config.overlay.tor_control = Some(SocketAddr::from(([127, 0, 0, 1], 19052)));
    config.overlay.identity_dir = dir.path().to_path_buf();
    let service = P2pService::new(config, Arc::new(AtomicBool::new(false)));
    service
        .start(
            None,
            None,
            &idle_ready(),
            crate::listener::ListenerExtras::default(),
        )
        .expect("overlay start succeeds");
    {
        let workers = service.workers.lock();
        let workers = workers.as_ref().expect("workers installed");
        assert_eq!(
            workers.listeners.len(),
            1,
            "overlay.start handles must be retained for rollback and join"
        );
    }
    service.shutdown();
    service.join().expect("join waits for overlay teardown");
}

#[test]
fn network_activity_transition_cancels_leases_only_when_disabled() {
    let table = crate::PeerTable::new();
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    table.register(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333)),
        lease.clone(),
    );
    let flag = AtomicBool::new(true);

    table.set_network_active(&flag, true);
    assert!(flag.load(Ordering::Acquire));
    assert!(!lease.is_cancelled());

    table.set_network_active(&flag, false);
    assert!(!flag.load(Ordering::Acquire));
    assert!(lease.is_cancelled());
}

#[test]
fn manual_connection_does_not_fill_automatic_full_relay_slot() {
    use crate::connection::PeerLease;
    use crate::peer_info::PeerRole;

    let table = crate::PeerTable::new();
    let (manual_tx, _manual_rx) = crossbeam_channel::unbounded();
    table.register(
        PeerEndpoint::from(([127, 0, 0, 1], 1)),
        PeerLease::new_manual(manual_tx, PeerRole::FullRelay),
    );
    let mut pending = HashMap::from([(
        PeerEndpoint::from(([127, 0, 0, 1], 2)),
        ActiveOutbound {
            feeler: false,

            role: PeerRole::FullRelay,
            manual: true,
        },
    )]);
    let automatic_dial = OutboundDial::auto(PeerEndpoint::from(([127, 0, 0, 1], 3)));

    assert_eq!(
        dial_outbound_role(&automatic_dial, &table, &pending, 1, 1, false),
        PeerRole::FullRelay,
        "manual peers and dials must not fill automatic slots"
    );
    assert!(
        has_automatic_outbound_capacity(&pending, 1, false),
        "a pending manual dial must not use automatic capacity"
    );

    pending.insert(
        PeerEndpoint::from(([127, 0, 0, 1], 4)),
        ActiveOutbound {
            feeler: false,

            role: PeerRole::FullRelay,
            manual: false,
        },
    );
    assert!(
        !has_automatic_outbound_capacity(&pending, 1, false),
        "a pending automatic dial must use automatic capacity"
    );
}

#[test]
fn next_outbound_role_fills_full_relay_slots_first() {
    use crate::connection::PeerLease;
    let table = crate::PeerTable::new();
    assert!(
        matches!(
            next_outbound_role(&table, &HashMap::new(), 1, 1, false),
            crate::peer_info::PeerRole::FullRelay
        ),
        "an empty table takes the full-relay slot first"
    );

    let (full_tx, _full_rx) = crossbeam_channel::unbounded();
    table.register(
        PeerEndpoint::from(([127, 0, 0, 1], 1)),
        PeerLease::new(full_tx),
    );
    assert!(
        matches!(
            next_outbound_role(&table, &HashMap::new(), 1, 1, false),
            crate::peer_info::PeerRole::BlockRelayOnly
        ),
        "the full-relay slot is held, so the next dial is block-relay"
    );
    assert!(
        matches!(
            next_outbound_role(&table, &HashMap::new(), 1, 1, true),
            crate::peer_info::PeerRole::FullRelay
        ),
        "a stale tip raises the full-relay target by one"
    );

    let (block_tx, _block_rx) = crossbeam_channel::unbounded();
    table.register(
        PeerEndpoint::from(([127, 0, 0, 1], 2)),
        PeerLease::new_block_relay(block_tx),
    );
    assert!(
        matches!(
            next_outbound_role(&table, &HashMap::new(), 1, 1, false),
            crate::peer_info::PeerRole::FullRelay
        ),
        "with both classes full, a requested dial stays full relay"
    );
}

#[test]
fn in_flight_dials_hold_their_class() {
    use crate::peer_info::PeerRole;

    let table = crate::PeerTable::new();
    let mut pending: HashMap<PeerEndpoint, ActiveOutbound> = HashMap::new();
    for port in 1..=8_u16 {
        pending.insert(
            PeerEndpoint::from(([127, 0, 0, 1], port)),
            ActiveOutbound {
                feeler: false,

                role: PeerRole::FullRelay,
                manual: false,
            },
        );
    }
    assert!(
        matches!(
            next_outbound_role(&table, &pending, 8, 2, false),
            PeerRole::BlockRelayOnly
        ),
        "eight unregistered full-relay dials already fill the full-relay slots"
    );
    for port in 9..=10_u16 {
        pending.insert(
            PeerEndpoint::from(([127, 0, 0, 1], port)),
            ActiveOutbound {
                feeler: false,

                role: PeerRole::BlockRelayOnly,
                manual: false,
            },
        );
    }
    assert!(
        matches!(
            next_outbound_role(&table, &pending, 8, 2, false),
            PeerRole::FullRelay
        ),
        "with both classes dialled full, a requested dial stays full relay"
    );
}

#[test]
fn a_registered_dial_counts_once() {
    use crate::connection::PeerLease;
    use crate::peer_info::PeerRole;

    let table = crate::PeerTable::new();
    let mut pending: HashMap<PeerEndpoint, ActiveOutbound> = HashMap::new();
    for port in 1..=5_u16 {
        let addr = PeerEndpoint::from(([127, 0, 0, 1], port));
        let (tx, _rx) = crossbeam_channel::unbounded();
        table.register(addr, PeerLease::new(tx));
        pending.insert(
            addr,
            ActiveOutbound {
                feeler: false,

                role: PeerRole::FullRelay,
                manual: false,
            },
        );
    }
    assert!(
        matches!(
            next_outbound_role(&table, &pending, 8, 2, false),
            PeerRole::FullRelay
        ),
        "five connected full-relay peers hold five of eight slots, not ten"
    );
}

#[test]
fn newest_excess_full_relay_picks_the_newest_aged_connection() {
    use crate::connection::PeerLease;
    use crate::download_window::MINIMUM_CONNECT_TIME;
    use crate::peer_info::PeerRole;

    fn addr(port: u16) -> PeerEndpoint {
        PeerEndpoint::from(([127, 0, 0, 1], port))
    }

    let now = Instant::now();
    let aged = now
        .checked_sub(MINIMUM_CONNECT_TIME)
        .expect("test clock is past the minimum connect time");
    let table = crate::PeerTable::new();
    for port in 1..=2_u16 {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut lease = PeerLease::new(tx);
        lease.backdate_for_test(aged);
        table.register(addr(port), lease);
    }
    let (block_tx, _block_rx) = crossbeam_channel::unbounded();
    let mut block_lease = PeerLease::new_block_relay(block_tx);
    block_lease.backdate_for_test(aged);
    table.register(addr(3), block_lease);
    let (inbound_tx, _inbound_rx) = crossbeam_channel::unbounded();
    let mut inbound_lease = PeerLease::new_inbound(inbound_tx);
    inbound_lease.backdate_for_test(aged);
    table.register(addr(4), inbound_lease);

    assert!(
        newest_excess_full_relay(&table, 2, now, |_| false).is_none(),
        "two full-relay connections fill two slots, and neither a              block-relay nor an inbound connection counts as one"
    );

    let (young_tx, _young_rx) = crossbeam_channel::unbounded();
    let young_lease = PeerLease::new(young_tx);
    table.register(addr(5), young_lease);
    let (third_tx, _third_rx) = crossbeam_channel::unbounded();
    let mut third_lease = PeerLease::new(third_tx);
    third_lease.backdate_for_test(aged);
    table.register(addr(6), third_lease);

    let excess = newest_excess_full_relay(&table, 2, now, |_| false)
        .expect("three full-relay peers are one extra");
    assert_eq!(
        excess.addr,
        crate::PeerRemote::Endpoint(addr(6)),
        "the newest aged connection is the one"
    );
    assert_eq!(excess.lease.role(), PeerRole::FullRelay);

    let (pinned_tx, _pinned_rx) = crossbeam_channel::unbounded();
    let mut pinned_lease = PeerLease::new_manual(pinned_tx, PeerRole::FullRelay);
    pinned_lease.backdate_for_test(aged);
    table.register(addr(7), pinned_lease);
    assert_eq!(
        newest_excess_full_relay(&table, 2, now, |_| false)
            .expect("the pinned connection is not a candidate")
            .endpoint
            .expect("identified excess peer"),
        excess.endpoint.expect("identified excess peer"),
        "the newest automatic connection stays the victim while a pinned one is newer"
    );
}

#[test]
fn a_pinned_dial_takes_full_relay_whatever_the_slots_hold() {
    use crate::connection::PeerLease;
    use crate::peer_info::PeerRole;

    let table = crate::PeerTable::new();
    let addr = PeerEndpoint::from(([127, 0, 0, 1], 1));
    let (tx, _rx) = crossbeam_channel::unbounded();
    table.register(addr, PeerLease::new(tx));

    assert!(
        matches!(
            next_outbound_role(&table, &HashMap::new(), 1, 1, false),
            PeerRole::BlockRelayOnly
        ),
        "premise: the automatic chooser answers a full slot with block relay"
    );
    assert!(
        matches!(
            dial_outbound_role(
                &OutboundDial::pinned(PeerEndpoint::from(([127, 0, 0, 1], 2))),
                &table,
                &HashMap::new(),
                1,
                1,
                false,
            ),
            PeerRole::FullRelay
        ),
        "the operator's pin is answered with full relay regardless"
    );
}

#[test]
fn the_excess_victim_comes_from_the_excess_slice_only() {
    use crate::connection::PeerLease;
    use crate::download_window::MINIMUM_CONNECT_TIME;

    fn addr(port: u16) -> PeerEndpoint {
        PeerEndpoint::from(([127, 0, 0, 1], port))
    }

    let now = Instant::now();
    let aged = now
        .checked_sub(MINIMUM_CONNECT_TIME)
        .expect("test clock is past the minimum connect time");
    let table = crate::PeerTable::new();

    for port in 1..=2_u16 {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut lease = PeerLease::new(tx);
        lease.backdate_for_test(aged);
        table.register(addr(port), lease);
    }
    let (young_tx, _young_rx) = crossbeam_channel::unbounded();
    table.register(addr(3), PeerLease::new(young_tx));

    assert!(
        newest_excess_full_relay(&table, 2, now, |_| false).is_none(),
        "the only excess candidate is too young, so nobody in the slots is retired"
    );

    let (aged_tx, _aged_rx) = crossbeam_channel::unbounded();
    let mut downloading = PeerLease::new(aged_tx);
    downloading.backdate_for_test(aged);
    table.register(addr(4), downloading);
    let source = table
        .lease(addr(4))
        .map(|lease| lease.source(Some(addr(4))))
        .expect("the downloading excess peer is registered");

    assert!(
        newest_excess_full_relay(&table, 2, now, |candidate| candidate == source).is_none(),
        "the downloading excess peer is passed over and nothing else is beyond the slots"
    );
    assert_eq!(
        newest_excess_full_relay(&table, 2, now, |_| false)
            .expect("the aged excess peer is eligible")
            .addr,
        crate::PeerRemote::Endpoint(addr(4)),
        "the same peer is the victim once its download completes"
    );
}

#[test]
fn a_pinned_peer_beyond_a_full_set_creates_no_excess() {
    use crate::connection::PeerLease;
    use crate::download_window::MINIMUM_CONNECT_TIME;
    use crate::peer_info::PeerRole;

    fn addr(port: u16) -> PeerEndpoint {
        PeerEndpoint::from(([127, 0, 0, 1], port))
    }

    let now = Instant::now();
    let aged = now
        .checked_sub(MINIMUM_CONNECT_TIME)
        .expect("test clock is past the minimum connect time");
    let table = crate::PeerTable::new();

    for port in 1..=2_u16 {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut lease = PeerLease::new(tx);
        lease.backdate_for_test(aged);
        table.register(addr(port), lease);
    }
    let (pinned_tx, _pinned_rx) = crossbeam_channel::unbounded();
    let mut pinned_lease = PeerLease::new_manual(pinned_tx, PeerRole::FullRelay);
    pinned_lease.backdate_for_test(aged);
    table.register(addr(3), pinned_lease);

    assert!(
        newest_excess_full_relay(&table, 2, now, |_| false).is_none(),
        "a full automatic set plus a pinned peer is still no connection over"
    );

    let (extra_tx, _extra_rx) = crossbeam_channel::unbounded();
    let mut extra_lease = PeerLease::new(extra_tx);
    extra_lease.backdate_for_test(aged);
    table.register(addr(4), extra_lease);

    assert_eq!(
        newest_excess_full_relay(&table, 2, now, |_| false)
            .expect("three automatic connections are one extra")
            .addr,
        crate::PeerRemote::Endpoint(addr(4)),
        "a real automatic excess still retires its newest aged peer"
    );
}

#[test]
fn add_node_enqueues_and_respects_queue_capacity() {
    let service = P2pService::new(
        P2pServiceConfig {
            outbound_queue_limit: 1,
            ..P2pServiceConfig::default()
        },
        Arc::new(AtomicBool::new(false)),
    );
    let addr1: PeerEndpoint = "127.0.0.1:8333".parse().expect("addr");
    let addr2: PeerEndpoint = "127.0.0.2:8333".parse().expect("addr");

    assert!(service.add_node(addr1, true).is_ok());
    assert_eq!(service.added_nodes().as_slice(), &[addr1]);
    let dial = service.outbound_rx.lock().try_recv().expect("recv");
    assert_eq!(dial, OutboundDial::pinned(addr1));

    service
        .outbound_tx
        .try_send(OutboundDial::pinned(addr1))
        .expect("send");

    assert_eq!(
        service.add_node(addr2, false),
        Err(P2pControlError::QueueFull)
    );

    assert!(service.add_node(addr2, true).is_ok());
    assert_eq!(service.added_nodes().as_slice(), &[addr1, addr2]);
}

#[test]
fn add_node_inactive_skips_queueing() {
    let service = P2pService::new(
        P2pServiceConfig::default(),
        Arc::new(AtomicBool::new(false)),
    );
    service.set_network_active(false);
    let addr: PeerEndpoint = "127.0.0.1:8333".parse().expect("addr");
    assert!(service.add_node(addr, true).is_ok());
    assert_eq!(service.added_nodes().as_slice(), &[addr]);
    assert!(service.outbound_rx.lock().try_recv().is_err());
}

#[test]
fn add_node_rejects_banned_address() {
    let service = P2pService::new(
        P2pServiceConfig::default(),
        Arc::new(AtomicBool::new(false)),
    );
    let subnet: crate::IpSubnet = "127.0.0.0/24".parse().expect("subnet");
    service.set_ban(crate::BannedSubnet {
        subnet,
        ban_created: SystemTime::now(),
        banned_until: None,
        reason: String::new(),
    });
    let addr: PeerEndpoint = "127.0.0.1:8333".parse().expect("addr");
    assert_eq!(service.add_node(addr, true), Err(P2pControlError::Banned));
    assert_eq!(service.added_nodes().as_slice(), &[]);
    assert!(service.outbound_rx.lock().try_recv().is_err());
}
#[test]
fn parked_overflow_releases_the_address_for_another_selection() {
    let address = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333));
    let book = crate::addrman::AddressBook::open(None, [1; 4], true, None);
    book.learn_dns("seed", &[address], 10_000);
    book.queued(address);
    assert_eq!(book.select(&[], &[], 10_000, u64::MAX, |_| true), None);
    let mut parked = VecDeque::from(vec![OutboundDial::auto(address); MAX_PARKED_DIALS]);
    assert!(!park_automatic_dial(
        &mut parked,
        OutboundDial::auto(address),
        &book,
        &HashMap::new()
    ));
    assert_eq!(
        book.select(&[], &[], 10_000, u64::MAX, |_| true),
        Some(address)
    );
}
fn maintenance_fixture(target: usize) -> (AddressMaintenance, Receiver<OutboundDial>) {
    let (tx, rx) = crossbeam_channel::bounded(16);
    let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
    for n in 1..100 {
        let addr = PeerEndpoint::from(([8, n, 1, 1], 8333));
        book.learn_dns("seed", &[addr], 10_000);
        book.learn_peer(
            crate::PeerRemote::Endpoint(addr),
            &[(addr, 9, 10_000)],
            10_000,
        );
    }
    (
        AddressMaintenance {
            block_slots: 2,
            manual_nodes: Arc::new(RwLock::new(Vec::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            network_active: Arc::new(AtomicBool::new(true)),
            peer_table: Arc::new(crate::PeerTable::new()),
            outbound_tx: tx,
            port: 8333,
            seeds: Vec::new(),
            target,
            block_sync: None,
            chain_query: None,
            address_book: book,
            banned: BannedReader::fixture_empty(),
            routes: crate::RouteTable::default(),
        },
        rx,
    )
}

#[test]
fn fresh_unreachable_book_reseeds_on_a_bounded_cooldown() {
    let tick = Instant::now();
    let mut next = tick + Duration::from_secs(60);
    assert!(!dns_recovery_due(64, 0, 8, tick, &mut next));
    assert!(dns_recovery_due(
        64,
        0,
        8,
        tick + Duration::from_secs(60),
        &mut next
    ));
    assert!(!dns_recovery_due(
        64,
        0,
        8,
        tick + Duration::from_secs(61),
        &mut next
    ));
    assert!(!dns_recovery_due(
        64,
        8,
        8,
        tick + Duration::from_secs(120),
        &mut next
    ));
    assert!(dns_recovery_due(
        64,
        7,
        8,
        tick + Duration::from_secs(120),
        &mut next
    ));
    assert_eq!(next, tick + Duration::from_secs(180));
}

#[test]
fn block_relay_readiness_counts_for_dns_without_refreshing_gossip_time() {
    let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
    let full = PeerEndpoint::from(([8, 1, 1, 1], 8333));
    book.learn_dns("seed", &[full], 5000);
    let block = (2..=255)
        .map(|n| PeerEndpoint::from(([8, n, 1, 1], 8333)))
        .find(|peer| {
            book.learn_dns("seed", &[*peer], 5000);
            book.len() == 2
        })
        .expect("distinct candidate slot");
    let table = crate::PeerTable::new();
    for (addr, block_only) in [(full, false), (block, true)] {
        let (tx, _) = crossbeam_channel::bounded(1);
        let lease = if block_only {
            crate::PeerLease::new_block_relay(tx)
        } else {
            crate::PeerLease::new(tx)
        };
        table.register(addr, lease.clone());
        let info = crate::PeerInfo {
            addr: crate::PeerRemote::Endpoint(addr),
            endpoint: Some(addr),
            network: addr.net(),
            version: 70016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 9,
            user_agent: String::new(),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: crate::TransportRemote::new(
                addr.socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            ),
            time_offset: 0,
            counters: Arc::new(crate::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
        };
        assert!(table.publish_info(addr, &lease, info));
    }
    assert_eq!(ready_address_count(&table, &book), 2);
    assert!(book.queued_feeler(block));
    assert_eq!(
        ready_address_count(&table, &book),
        1,
        "exclude ready feelers"
    );
    book.reject_queued(block, true);
    assert_eq!(ready_address_count(&table, &book), 2);
    let response = book.gossip(10_000);
    for (addr, expected) in [(full, 5000), (block, 5000)] {
        let timestamp = response
            .iter()
            .find(|advertised| advertised.socket_addr().ok().map(PeerEndpoint::from) == Some(addr))
            .expect("advertised")
            .time;
        assert_eq!(
            timestamp, expected,
            "active connections never refresh gossip timestamp"
        );
    }
}

#[test]
fn failure_accounting_uses_persistent_tcp_groups_including_manual_before_ready() {
    let table = crate::PeerTable::new();
    let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
    assert!(!count_address_failure(&table, 125, &book));
    assert!(count_address_failure(&table, 1, &book));
    let (tx, _) = crossbeam_channel::bounded(1);
    let automatic = crate::PeerLease::new(tx.clone());
    table.register(PeerEndpoint::from(([8, 1, 1, 1], 8333)), automatic);
    assert!(!count_address_failure(&table, 125, &book));
    assert!(count_address_failure(&table, 2, &book));
    let same_group = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
    table.register(PeerEndpoint::from(([8, 1, 2, 2], 8333)), same_group);
    assert!(!count_address_failure(&table, 125, &book));
    let manual = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
    table.register(PeerEndpoint::from(([8, 2, 1, 1], 8333)), manual.clone());
    assert!(
        table
            .sessions()
            .iter()
            .all(|session| session.info.is_none())
    );
    assert!(
        count_address_failure(&table, 125, &book),
        "Core counts established TCP sessions before handshake publication"
    );
    manual.cancel();
    let probe = PeerEndpoint::from(([9, 4, 1, 1], 8333));
    assert!(book.queued_feeler(probe));
    let probe_lease = register_ready_block_peer(&table, probe);
    assert!(!count_address_failure(&table, 125, &book));
    assert!(count_address_failure(&table, 2, &book));
    assert_eq!(ready_address_count(&table, &book), 0);
    assert_eq!(anchor_peers(&table, &book), Vec::<PeerEndpoint>::new());
    table.remove_current(probe, &probe_lease);
    book.unqueue(probe);
    table.register(
        PeerEndpoint::from(([8, 3, 1, 1], 8333)),
        crate::PeerLease::new_inbound(tx),
    );
    assert!(
        !count_address_failure(&table, 125, &book),
        "inbound and cancelled sessions do not certify connectivity"
    );
}

#[test]
fn failure_census_uses_the_same_configured_asmap_for_persistent_tcp_sessions() {
    let directory = tempfile::tempdir().expect("directory");
    let map = directory.path().join("asmap.raw");
    std::fs::write(
        &map,
        include_bytes!("../../tests/data/asmap-source-quota-core-v31.1.raw"),
    )
    .expect("Core map");
    let book = crate::addrman::AddressBook::open(None, [1; 4], false, Some(&map));
    let table = crate::PeerTable::new();
    let (tx, _) = crossbeam_channel::bounded(1);
    table.register(
        "8.8.0.1:8333".parse::<PeerEndpoint>().expect("peer"),
        crate::PeerLease::new(tx.clone()),
    );
    table.register(
        "9.9.0.1:8333".parse::<PeerEndpoint>().expect("same ASN"),
        crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay),
    );
    assert!(
        !count_address_failure(&table, 125, &book),
        "different prefixes in one ASN count once"
    );
    assert!(count_address_failure(&table, 2, &book));
    let independent = crate::PeerLease::new_manual(tx.clone(), crate::PeerRole::FullRelay);
    table.register(
        "8.8.1.1:8333"
            .parse::<PeerEndpoint>()
            .expect("independent ASN"),
        independent.clone(),
    );
    assert!(
        table
            .sessions()
            .iter()
            .all(|session| session.info.is_none())
    );
    assert!(
        count_address_failure(&table, 125, &book),
        "independent ASN in same /16 establishes second group"
    );
    std::fs::remove_file(&map).expect("loaded map stays immutable");
    assert!(count_address_failure(&table, 125, &book));
    independent.cancel();
    table.register(
        "8.8.1.2:8333".parse::<PeerEndpoint>().expect("inbound"),
        crate::PeerLease::new_inbound(tx),
    );
    assert!(!count_address_failure(&table, 125, &book));
}

#[test]
fn auxiliary_save_interval_retains_immediate_explicit_save() {
    let dir = tempfile::tempdir().expect("dir");
    let base = dir.path().join("peers.dat");
    let book = crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true, None);
    let addr = PeerEndpoint::from(([127, 0, 0, 1], 8333));
    book.learn_dns("seed", &[addr], 10_000);
    let tick = Instant::now();
    let mut next = tick + Duration::from_mins(15);
    save_address_book_if_due(&book, tick, &mut next);
    assert_eq!(
        crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true, None).len(),
        0
    );
    save_address_book_if_due(&book, tick + Duration::from_mins(15), &mut next);
    assert_eq!(
        crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true, None).len(),
        1
    );
    book.connected(addr, 20_000);
    save_address_book_if_due(&book, tick + Duration::from_secs(901), &mut next);
    assert_eq!(
        crate::addrman::AddressBook::open(Some(base.clone()), [1; 4], true, None).gossip(20_000)[0]
            .time,
        10_000
    );
    book.save();
    assert_eq!(
        crate::addrman::AddressBook::open(Some(base), [1; 4], true, None).gossip(20_000)[0].time,
        20_000,
        "shutdown and anchor-consumption barriers bypass the periodic throttle"
    );
}

#[test]
fn automatic_policy_and_manual_bans_are_distinct() {
    let ip: std::net::IpAddr = "8.8.8.8".parse().expect("ip");
    let protected: crate::IpSubnet = "8.8.8.0/24".parse().expect("subnet");
    let service = P2pService::new(
        P2pServiceConfig {
            noban_subnets: vec![protected],
            ..Default::default()
        },
        Arc::new(AtomicBool::new(false)),
    );
    let reader = service.banned_reader();
    reader.discourage(ip);
    assert!(
        reader.is_noban(
            "::ffff:8.8.8.8"
                .parse::<std::net::IpAddr>()
                .expect("mapped ip")
        )
    );
    assert!(reader.automatic_snapshot(SystemTime::now()).allows(ip));
    service.set_ban(crate::BannedSubnet {
        subnet: protected,
        banned_until: None,
        ban_created: SystemTime::now(),
        reason: "manual".into(),
    });
    assert!(!reader.automatic_snapshot(SystemTime::now()).allows(ip));
    service.clear_banned();
    assert!(reader.automatic_snapshot(SystemTime::now()).allows(ip));
}

#[test]
fn all_automatic_selection_classes_exclude_discouraged_addresses() {
    let (maintenance, queue) = maintenance_fixture(4);
    let now = crate::addrman::now();
    for n in 1..100 {
        let addr = PeerEndpoint::from(([8, n, 1, 1], 8333));
        maintenance.address_book.learn_dns("seed", &[addr], now);
        maintenance.address_book.learn_peer(
            crate::PeerRemote::Endpoint(addr),
            &[(addr, 9, now)],
            now,
        );
    }
    assert!(
        maintenance
            .address_book
            .select(&[], &[], now, u64::MAX, |_| true)
            .is_some()
    );
    assert!(
        maintenance
            .address_book
            .feeler(&[], &[], now, |_| true)
            .is_some()
    );
    for n in 1..100 {
        maintenance
            .banned
            .discourage(std::net::IpAddr::from([8, n, 1, 1]));
    }
    queue_address_candidates(&maintenance, now, SystemTime::now(), 0);
    assert!(
        queue.is_empty(),
        "regular selection must apply the policy snapshot"
    );
    let address = PeerEndpoint::from(([8, 1, 1, 1], 8333));
    maintenance.address_book.succeeded(address, 9, now);
    maintenance.address_book.remember_anchors(&[address], now);
    let mut anchors: VecDeque<_> = maintenance.address_book.take_restart_anchors(now).into();
    assert!(
        maintenance.address_book.anchor_eligible(address, &[], now),
        "anchor must otherwise be eligible"
    );
    queue_restart_anchors(&maintenance, &mut anchors, &mut None, &mut Vec::new(), now);
    assert!(
        !maintenance.address_book.is_pending(address),
        "a discouraged anchor must release its standby reservation"
    );
    assert!(
        queue.is_empty(),
        "restart anchors must apply the same policy"
    );
    let (headers, _) = crossbeam_channel::unbounded();
    let (blocks, _) = crossbeam_channel::unbounded();
    let shared = crate::listener::ConnectionShared::new(
        Arc::clone(&maintenance.peer_table),
        maintenance.banned.clone(),
        Arc::new(crate::NetworkActivity::from_shared(Arc::clone(
            &maintenance.network_active,
        ))),
        bitcoin_rs_chain::LatchReader::new(Arc::clone(&maintenance.shutdown)),
        None,
        Magic::BITCOIN,
        headers,
        blocks,
        None,
        None,
        crate::listener::ListenerExtras::default(),
    );
    let mut active = HashMap::new();
    let mut handles = Vec::new();
    spawn_feeler(
        &shared,
        &maintenance.address_book,
        &[],
        &mut active,
        &mut handles,
        DEFAULT_MAX_PEER_CONNECTIONS,
    );
    assert!(
        active.is_empty() && handles.is_empty(),
        "feeler selection must not start a discouraged dial"
    );
}

#[test]
fn maintenance_counts_queued_parked_and_inflight_automatic_claims_once() {
    let (mut maintenance, rx) = maintenance_fixture(3);
    let tick = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    queue_address_candidates(&maintenance, 10_000, tick, 0);
    assert_eq!(rx.len(), 3);
    for _ in 0..4 {
        queue_address_candidates(&maintenance, 10_000, tick, 0);
    }
    assert_eq!(
        rx.len(),
        3,
        "ticks cannot keep filling a pending dial pipeline"
    );
    let parked = rx.try_recv().expect("queued");
    queue_address_candidates(&maintenance, 10_000, tick, 0);
    assert_eq!(rx.len(), 2, "parking keeps the claim occupied");
    maintenance
        .address_book
        .attempted(parked.addr, true, 10_001);
    queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100), 0);
    assert_eq!(
        rx.len(),
        2,
        "a slow connect keeps capacity occupied beyond retry backoff"
    );
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    maintenance.peer_table.register(parked.addr, lease.clone());
    maintenance.address_book.succeeded(parked.addr, 9, 10_100);
    maintenance.target = 4;
    queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100), 0);
    assert_eq!(rx.len(), 3, "the live session and its claim count once");
    let (tx, _rx) = crossbeam_channel::unbounded();
    maintenance.peer_table.register(
        PeerEndpoint::from(([9, 9, 1, 1], 8333)),
        crate::PeerLease::new_manual(tx, crate::PeerRole::FullRelay),
    );
    maintenance.target = 5;
    queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100), 0);
    assert_eq!(
        rx.len(),
        4,
        "manual sessions do not consume automatic slots"
    );
    lease.cancel();
    maintenance.address_book.unqueue(parked.addr);
    queue_address_candidates(&maintenance, 10_100, tick + Duration::from_secs(100), 0);
    assert_eq!(
        rx.len(),
        5,
        "finished cancelled automatic claims release their slot"
    );
}

#[test]
fn selection_uses_one_ban_snapshot_at_the_tick_time() {
    let (maintenance, rx) = maintenance_fixture(1);
    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(10_001);
    maintenance.banned.inner.write().push(crate::BannedSubnet {
        subnet: "8.0.0.0/8".parse().expect("subnet"),
        banned_until: Some(until),
        ban_created: SystemTime::UNIX_EPOCH,
        reason: String::new(),
    });
    queue_address_candidates(&maintenance, 10_000, until - Duration::from_secs(1), 0);
    assert_eq!(
        rx.len(),
        0,
        "the entire banned subnet is excluded before expiry"
    );
    queue_address_candidates(&maintenance, 10_001, until, 0);
    assert_eq!(
        rx.len(),
        1,
        "expiry uses the supplied tick, not a later wall clock read"
    );
}

#[test]
fn shutdown_releases_parked_automatic_claims_before_restart() {
    let service = P2pService::new(
        P2pServiceConfig {
            outbound_full_relay_slots: 0,
            outbound_block_relay_slots: 0,
            allow_local_addresses: true,
            dns_seeds_enabled: false,
            ..P2pServiceConfig::default()
        },
        Arc::new(AtomicBool::new(false)),
    );
    let address = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333));
    let now = crate::addrman::now();
    service.address_book.learn_dns("seed", &[address], now);
    service.address_book.queued(address);
    service
        .outbound_tx
        .try_send(OutboundDial::auto(address))
        .expect("queue");
    service
        .start(
            None,
            None,
            &idle_ready(),
            crate::listener::ListenerExtras::default(),
        )
        .expect("start");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if service
            .outbound_rx
            .try_lock()
            .is_some_and(|rx| rx.is_empty())
        {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        service.outbound_rx.lock().is_empty(),
        "worker must have parked the request"
    );
    assert_eq!(service.address_book.pending_count_excluding(&[]), 1);
    service.shutdown();
    service.join().expect("join");
    assert_eq!(service.address_book.pending_count_excluding(&[]), 0);
    assert_eq!(
        service
            .address_book
            .select(&[], &[], now, u64::MAX, |_| true),
        Some(address)
    );
    service.set_network_active(true);
    service
        .start(
            None,
            None,
            &idle_ready(),
            crate::listener::ListenerExtras::default(),
        )
        .expect("restart");
    service.shutdown();
    service.join().expect("restarted join");
}

#[test]
fn manual_dial_cannot_release_an_automatic_claim_and_reaper_releases_only_its_owner() {
    let table = Arc::new(crate::PeerTable::new());
    let (headers, _) = crossbeam_channel::bounded(1);
    let (blocks, _) = crossbeam_channel::bounded(1);
    let mut shared = crate::listener::ConnectionShared::new(
        table,
        BannedReader::fixture_empty(),
        Arc::new(crate::NetworkActivity::from_shared(Arc::new(
            AtomicBool::new(true),
        ))),
        Arc::new(AtomicBool::new(false)),
        None,
        Magic::REGTEST,
        headers,
        blocks,
        None,
        None,
        crate::listener::ListenerExtras::default(),
    );
    let book = crate::addrman::AddressBook::open(None, [1; 4], true, None);
    shared.address_book = Some(book.clone());
    let address = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333));
    book.queued(address);
    let mut active = HashMap::from([(
        address,
        ActiveOutbound {
            feeler: false,

            role: crate::PeerRole::FullRelay,
            manual: true,
        },
    )]);
    let mut handles = Vec::new();
    spawn_outbound_dial(
        &OutboundDial::pinned(address),
        &shared,
        &mut active,
        &mut handles,
        1,
        0,
        false,
        DEFAULT_MAX_PEER_CONNECTIONS,
    );
    assert_eq!(
        book.pending_count_excluding(&[]),
        1,
        "manual duplicate must not clear the automatic owner"
    );
    for manual in [true, false] {
        active.insert(
            address,
            ActiveOutbound {
                feeler: false,

                role: crate::PeerRole::FullRelay,
                manual,
            },
        );
        handles.push((address, thread::spawn(|| Ok(()))));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !handles.is_empty() && Instant::now() < deadline {
            let _ = reap_finished_outbound_connections(&mut active, &mut handles, &book);
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(handles.len(), 0);
        assert_eq!(book.pending_count_excluding(&[]), usize::from(manual));
    }
}

#[test]
fn anchors_require_automatic_block_relay_and_demonstrated_chain_evidence() {
    let book = crate::addrman::AddressBook::open(None, [1; 4], true, None);
    let table = crate::PeerTable::new();
    let mut leases = Vec::new();
    for port in 1..=4_u16 {
        let address = PeerEndpoint::from((Ipv4Addr::LOCALHOST, port));
        let (sender, _receiver) = crossbeam_channel::unbounded();
        let lease = match port {
            1 | 2 => crate::PeerLease::new_block_relay(sender),
            3 => crate::PeerLease::new_manual(sender, crate::PeerRole::BlockRelayOnly),
            _ => crate::PeerLease::new(sender),
        };
        let version = crate::handshake::version_message(
            1,
            1_000_000,
            crate::PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        );
        let info = crate::PeerInfo::outbound_from_version(
            address,
            address
                .socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
            &version,
            10_000,
            10_000,
            Arc::new(crate::PeerCounters::default()),
        );
        table.register(address, lease.clone());
        assert!(table.publish_info(address, &lease, info));
        if port != 1 {
            assert!(table.note_announced_tip(
                lease.source(Some(address)),
                bitcoin_rs_primitives::Hash256::from_le_bytes(&[7; 32]),
                Some(2)
            ));
        }
        leases.push(lease);
    }
    assert_eq!(
        anchor_peers(&table, &book),
        vec![PeerEndpoint::from((Ipv4Addr::LOCALHOST, 2))]
    );
    leases[1].cancel();
    assert_eq!(anchor_peers(&table, &book), Vec::<PeerEndpoint>::new());
}

#[test]
fn anchor_dials_prefer_block_slots_without_displacing_manual_roles() {
    let table = crate::PeerTable::new();
    let address = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333));
    let anchor = OutboundDial {
        addr: address,
        manual: false,
        purpose: DialPurpose::Anchor,
    };
    assert_eq!(
        dial_outbound_role(&anchor, &table, &HashMap::new(), 8, 2, false),
        crate::PeerRole::BlockRelayOnly
    );
    assert_eq!(
        dial_outbound_role(
            &OutboundDial::pinned(address),
            &table,
            &HashMap::new(),
            8,
            2,
            false
        ),
        crate::PeerRole::FullRelay
    );
    let mut pending = HashMap::new();
    pending.insert(
        address,
        ActiveOutbound {
            feeler: true,

            manual: false,
            role: crate::PeerRole::BlockRelayOnly,
        },
    );
    assert!(
        has_automatic_outbound_capacity(&pending, 1, false),
        "a probe does not consume a steady slot"
    );
    assert_eq!(
        next_outbound_role(&table, &pending, 0, 1, false),
        crate::PeerRole::BlockRelayOnly
    );
}

#[test]
fn anchor_queue_preserves_diversity_and_releases_a_saturated_attempt() {
    let (mut maintenance, _) = maintenance_fixture(2);
    let (sender, receiver) = crossbeam_channel::bounded(1);
    maintenance.outbound_tx = sender;
    let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
    maintenance.address_book = Arc::clone(&book);
    let first: PeerEndpoint = "8.1.1.1:8333".parse().expect("first");
    let other: PeerEndpoint = "9.2.1.1:8333".parse().expect("other");
    for addr in [first, other] {
        book.learn_dns("seed", &[addr], 10_000);
        book.succeeded(addr, 9, 10_001);
    }
    book.remember_anchors(&[first, other], 10_001);
    let mut anchors: VecDeque<_> = book.take_restart_anchors(10_002).into();
    let mut current = None;
    let mut active = Vec::new();
    maintenance
        .outbound_tx
        .try_send(OutboundDial::pinned(first))
        .expect("saturate");
    assert_eq!(
        queue_restart_anchors(
            &maintenance,
            &mut anchors,
            &mut current,
            &mut active,
            10_002
        ),
        2
    );
    assert!(book.anchor_eligible(first, &[], 10_002));
    assert!(receiver.try_recv().expect("drain").manual);
    queue_restart_anchors(
        &maintenance,
        &mut anchors,
        &mut current,
        &mut active,
        10_002,
    );
    assert_eq!(receiver.try_recv().expect("first").addr, first);
    assert!(book.anchor_dispatched(first));
    let _lease = register_ready_block_peer(&maintenance.peer_table, first);
    queue_restart_anchors(
        &maintenance,
        &mut anchors,
        &mut current,
        &mut active,
        10_003,
    );
    assert_eq!(receiver.try_recv().expect("diverse second").addr, other);
    assert_eq!(anchors, VecDeque::<PeerEndpoint>::new());
    book.defer_anchor(other);
    book.return_restart_anchors(10_004);
    assert_eq!(book.take_restart_anchors(10_004), vec![other]);
    maintenance.manual_nodes.write().push(other);
    let mut pinned = VecDeque::from(vec![other]);
    queue_restart_anchors(
        &maintenance,
        &mut pinned,
        &mut None,
        &mut Vec::new(),
        10_004,
    );
    assert!(receiver.try_recv().is_err());
    book.return_restart_anchors(10_004);
    assert!(!book.is_pending(other));
}

#[test]
fn a_queued_or_registered_probe_never_occupies_a_steady_outbound_slot() {
    for registered in [false, true] {
        let (maintenance, receiver) = maintenance_fixture(1);
        let book = &maintenance.address_book;
        let probe = book
            .select(&[], &[], 10_000, u64::MAX, |_| true)
            .expect("probe candidate");
        assert!(book.queued_feeler(probe));
        book.attempted(probe, true, 10_000);
        assert_eq!(book.pending_count_excluding(&[]), 0);
        let (sender, _receiver) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_block_relay(sender);
        if registered {
            maintenance.peer_table.register(probe, lease.clone());
        }
        queue_address_candidates(
            &maintenance,
            10_001,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10_001),
            0,
        );
        let regular = receiver
            .try_recv()
            .expect("the vacant steady slot is filled while probe is in flight");
        assert_ne!(regular.addr, probe);
        assert_eq!(regular.purpose, DialPurpose::Regular);
        queue_address_candidates(
            &maintenance,
            10_002,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10_002),
            0,
        );
        assert!(
            receiver.try_recv().is_err(),
            "the steady claim itself still fills its slot"
        );
        maintenance.peer_table.remove_current(probe, &lease);
        book.unqueue(probe);
        queue_address_candidates(
            &maintenance,
            10_003,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10_003),
            0,
        );
        assert!(receiver.try_recv().is_err());
    }
}
#[test]
fn mapped_manual_pins_exclude_all_automatic_dial_classes_without_rewriting_configuration() {
    let (maintenance, queue) = maintenance_fixture(4);
    let now = crate::addrman::now();
    for n in 1..100 {
        maintenance.address_book.learn_dns(
            "seed",
            &[PeerEndpoint::from(([8, n, 1, 1], 8333))],
            now,
        );
    }
    let book = &maintenance.address_book;
    let anchor = book
        .select(&[], &[], now, u64::MAX, |_| true)
        .expect("eligible ordinary candidate");
    book.succeeded(anchor, 9, now);
    book.remember_anchors(&[anchor], now);
    assert_eq!(book.take_restart_anchors(now), vec![anchor]);
    assert!(
        book.anchor_eligible(anchor, &[], now),
        "the anchor would otherwise be selectable"
    );
    assert!(
        book.feeler(&[], &[], now, |_| true).is_some(),
        "unproven probe candidates exist"
    );
    for n in 1..100 {
        maintenance.manual_nodes.write().push(PeerEndpoint::new(
            std::net::IpAddr::V6(Ipv4Addr::new(8, n, 1, 1).to_ipv6_mapped()),
            8333,
        ));
    }
    queue_address_candidates(&maintenance, now, SystemTime::now(), 0);
    assert!(
        queue.try_recv().is_err(),
        "ordinary selection must honor a mapped spelling of a manual pin"
    );
    let mut anchors = VecDeque::from(vec![anchor]);
    queue_restart_anchors(&maintenance, &mut anchors, &mut None, &mut Vec::new(), now);
    assert!(
        queue.try_recv().is_err(),
        "anchor selection must honor mapped manual pins"
    );
    assert_eq!(anchors, VecDeque::<PeerEndpoint>::new());
    let (headers, _) = crossbeam_channel::bounded(1);
    let (blocks, _) = crossbeam_channel::bounded(1);
    let mut shared = crate::listener::ConnectionShared::new(
        Arc::clone(&maintenance.peer_table),
        maintenance.banned.clone(),
        Arc::new(crate::NetworkActivity::from_shared(Arc::new(
            AtomicBool::new(false),
        ))),
        Arc::new(AtomicBool::new(false)),
        None,
        Magic::REGTEST,
        headers,
        blocks,
        None,
        None,
        crate::listener::ListenerExtras::default(),
    );
    shared.address_book = Some(Arc::clone(book));
    let pins = maintenance.manual_nodes.read().clone();
    let mut active = HashMap::new();
    let mut handles = Vec::new();
    spawn_feeler(
        &shared,
        book,
        &pins,
        &mut active,
        &mut handles,
        DEFAULT_MAX_PEER_CONNECTIONS,
    );
    let spawned = handles.len();
    for (_, handle) in handles {
        let _ = handle.join();
    }
    assert_eq!(spawned, 0, "feeler selection must honor mapped manual pins");
    assert!(active.is_empty());
    assert!(
        maintenance
            .manual_nodes
            .read()
            .iter()
            .all(PeerEndpoint::is_ipv6),
        "operator spelling is retained"
    );
    assert!(
        !is_manual_endpoint(&pins, PeerEndpoint::new(anchor.address(), 8334)),
        "a different port is a different endpoint"
    );
}
#[test]
fn onlynet_prefilter_selects_no_forbidden_network_dial() {
    let (mut maintenance, queue) = maintenance_fixture(4);
    maintenance.routes.onlynet = vec![crate::NetworkLabel::Onion];
    let now = 10_000;
    queue_address_candidates(&maintenance, now, SystemTime::now(), 0);
    assert!(
        queue.try_recv().is_err(),
        "an IP-heavy book under onlynet=onion must queue no ordinary dial"
    );
    let book = &maintenance.address_book;
    let anchor = book
        .select(&[], &[], now, u64::MAX, |_| true)
        .expect("eligible ordinary candidate");
    book.succeeded(anchor, 9, now);
    book.remember_anchors(&[anchor], now);
    assert_eq!(book.take_restart_anchors(now), vec![anchor]);
    assert!(
        book.anchor_eligible(anchor, &[], now),
        "the anchor would otherwise be selectable"
    );
    let mut anchors = VecDeque::from(vec![anchor]);
    queue_restart_anchors(&maintenance, &mut anchors, &mut None, &mut Vec::new(), now);
    assert!(
        queue.try_recv().is_err(),
        "anchor selection must honor the route prefilter"
    );
}
fn register_ready_block_peer(table: &crate::PeerTable, addr: PeerEndpoint) -> crate::PeerLease {
    let (sender, _receiver) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new_block_relay(sender);
    let version = crate::handshake::version_message(
        1,
        0,
        crate::PeerRole::FullRelay,
        ServiceFlags::NETWORK | ServiceFlags::WITNESS,
    );
    let info = crate::PeerInfo::outbound_from_version(
        addr,
        addr.socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
        &version,
        10_000,
        10_000,
        Arc::new(crate::PeerCounters::default()),
    );
    table.register(addr, lease.clone());
    assert!(table.publish_info(addr, &lease, info));
    assert!(table.note_announced_tip(
        lease.source(Some(addr)),
        bitcoin_rs_primitives::Hash256::from_le_bytes(&[7; 32]),
        Some(1)
    ));
    lease
}

#[test]
fn failed_first_anchor_retains_the_second_for_a_single_block_slot() {
    for target in [1, 2] {
        let (mut maintenance, queue) = maintenance_fixture(target);
        maintenance.block_slots = 1;
        let book = crate::addrman::AddressBook::open(None, [1; 4], false, None);
        maintenance.address_book = Arc::clone(&book);
        let first: PeerEndpoint = "8.1.1.1:8333".parse().expect("first");
        let second: PeerEndpoint = "9.2.1.1:8333".parse().expect("second");
        let full: PeerEndpoint = "11.3.1.1:8333".parse().expect("ordinary full relay");
        for addr in [first, second, full] {
            book.learn_dns("seed", &[addr], 10_000);
        }
        for addr in [first, second] {
            book.succeeded(addr, 9, 10_001);
        }
        book.remember_anchors(&[first, second], 10_001);
        let mut anchors: VecDeque<_> = book.take_restart_anchors(10_002).into();
        assert_eq!(
            book.pending_count_excluding(&[]),
            0,
            "standby reservations consume no steady capacity"
        );
        let mut current = None;
        let reserved = queue_restart_anchors(
            &maintenance,
            &mut anchors,
            &mut current,
            &mut Vec::new(),
            10_002,
        );
        assert_eq!(queue.try_recv().expect("first anchor").addr, first);
        assert_eq!(
            book.pending_count_excluding(&[]),
            1,
            "only the queued first attempt consumes a slot"
        );
        assert!(book.anchor_dispatched(first));
        book.attempted(first, true, 10_002);
        queue_address_candidates(
            &maintenance,
            10_002,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10_002),
            reserved,
        );
        if target == 2 {
            let ordinary = queue
                .try_recv()
                .expect("the free full-relay slot remains usable");
            assert_eq!(ordinary.addr, full);
            assert_eq!(ordinary.purpose, DialPurpose::Regular);
        }
        assert!(
            queue.try_recv().is_err(),
            "ordinary selection must not steal the second anchor"
        );
        assert!(
            !book.queued_feeler(second),
            "a racing feeler cannot claim a reserved anchor"
        );
        assert_eq!(anchors, VecDeque::from(vec![second]));
        book.unqueue(first);
        let reserved = queue_restart_anchors(
            &maintenance,
            &mut anchors,
            &mut current,
            &mut Vec::new(),
            10_003,
        );
        let fallback = queue.try_recv().expect("second persisted anchor");
        assert_eq!(fallback.addr, second);
        assert_eq!(fallback.purpose, DialPurpose::Anchor);
        assert_eq!(
            dial_outbound_role(
                &fallback,
                &maintenance.peer_table,
                &HashMap::new(),
                target - 1,
                1,
                false
            ),
            crate::PeerRole::BlockRelayOnly
        );
        queue_address_candidates(
            &maintenance,
            10_003,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10_003),
            reserved,
        );
        assert!(queue.try_recv().is_err());
    }
}

#[test]
fn a_queued_anchor_waits_for_its_block_slot_without_blocking_a_full_slot() {
    let first: PeerEndpoint = "8.1.1.1:8333".parse().expect("first");
    let second: PeerEndpoint = "9.2.1.1:8333".parse().expect("second");
    let busy = HashMap::from([(
        first,
        ActiveOutbound {
            role: crate::PeerRole::BlockRelayOnly,
            manual: false,
            feeler: false,
        },
    )]);
    assert!(
        !dial_has_capacity(
            &OutboundDial {
                addr: second,
                manual: false,
                purpose: DialPurpose::Anchor
            },
            &busy,
            2,
            1,
            false
        ),
        "a queued anchor cannot oversubscribe a block slot"
    );
    assert!(dial_has_capacity(
        &OutboundDial::auto(second),
        &busy,
        2,
        1,
        false
    ));
}

#[test]
fn shutdown_captures_anchors_before_cancelling_workers() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("peers.dat");
    let service = P2pService::new(
        P2pServiceConfig {
            address_book_path: Some(path.clone()),
            magic: Magic::REGTEST,
            allow_local_addresses: true,
            ..P2pServiceConfig::default()
        },
        Arc::new(AtomicBool::new(false)),
    );
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 8333));
    let now = crate::addrman::now();
    service.address_book.learn_dns("fixture", &[addr], now);
    service.address_book.succeeded(addr, 9, now);
    let lease = register_ready_block_peer(&service.peer_table, addr);
    *service.workers.lock() = Some(Workers::default());
    assert!(service.workers.lock().is_some());
    service.shutdown();
    assert!(lease.is_cancelled(), "shutdown must cancel live sessions");
    let restored =
        crate::addrman::AddressBook::open(Some(path), Magic::REGTEST.to_bytes(), true, None);
    assert_eq!(restored.take_restart_anchors(now), vec![addr]);
}

#[test]
fn shutdown_captures_anchors_before_cancelling_worker_leases() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("peers.dat");
    let service = P2pService::new(
        P2pServiceConfig {
            address_book_path: Some(path.clone()),
            magic: Magic::REGTEST,
            allow_local_addresses: true,
            ..P2pServiceConfig::default()
        },
        Arc::new(AtomicBool::new(false)),
    );
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 8333)).into();
    let now = crate::addrman::now();
    service.address_book.learn_dns("fixture", &[addr], now);
    service.address_book.succeeded(addr, 9, now);
    let lease = register_ready_block_peer(&service.peer_table, addr);
    *service.workers.lock() = Some(Workers::default());
    service.shutdown();
    assert!(lease.is_cancelled(), "workers cancel every lease");
    let restored =
        crate::addrman::AddressBook::open(Some(path), Magic::REGTEST.to_bytes(), true, None);
    assert_eq!(restored.take_restart_anchors(now), vec![addr]);
}
fn saved_book(path: &std::path::Path) -> sonic_rs::Value {
    let bytes = std::fs::read(path).expect("saved book");
    sonic_rs::from_slice(&bytes[..bytes.len() - 32]).expect("book JSON")
}

#[test]
fn rejected_duplicates_preserve_active_feeler_and_dispatched_anchor_claims_until_join() {
    for feeler in [false, true] {
        let address: PeerEndpoint = "127.0.0.1:8333".parse().expect("address");
        let book = crate::addrman::AddressBook::open(None, [1; 4], true, None);
        book.learn_dns("seed", &[address], 10_000);
        if feeler {
            assert!(book.queued_feeler(address));
            assert!(
                !book.queued(address),
                "regular cannot acquire a feeler claim"
            );
        } else {
            book.succeeded(address, 9, 10_000);
            book.remember_anchors(&[address], 10_000);
            assert_eq!(book.take_restart_anchors(10_001), vec![address]);
            assert!(book.queue_anchor(address));
            assert!(book.anchor_dispatched(address));
        }
        let mut active = HashMap::from([(
            address,
            ActiveOutbound {
                manual: false,
                feeler,
                role: crate::PeerRole::BlockRelayOnly,
            },
        )]);
        let mut shared = crate::listener::ConnectionShared::new(
            Arc::new(crate::PeerTable::new()),
            BannedReader::fixture_empty(),
            Arc::new(crate::NetworkActivity::from_shared(Arc::new(
                AtomicBool::new(false),
            ))),
            Arc::new(AtomicBool::new(false)),
            None,
            Magic::REGTEST,
            crossbeam_channel::bounded(1).0,
            crossbeam_channel::bounded(1).0,
            None,
            None,
            crate::listener::ListenerExtras::default(),
        );
        shared.address_book = Some(Arc::clone(&book));
        let mapped = PeerEndpoint::new(
            std::net::IpAddr::V6(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
            8333,
        );
        let duplicate = OutboundDial::auto(mapped);
        let mut handles = Vec::new();
        spawn_outbound_dial(
            &duplicate,
            &shared,
            &mut active,
            &mut handles,
            1,
            1,
            false,
            125,
        );
        assert!(handles.is_empty());
        assert!(
            book.is_pending(address),
            "inactive duplicate must preserve active owner"
        );
        assert!(is_manual_endpoint(&[mapped], address));
        defer_rejected_dial(&duplicate, &book, &active);
        assert!(
            book.is_pending(address),
            "manual-policy rejection preserves active owner"
        );
        let mut parked = VecDeque::from(vec![duplicate; MAX_PARKED_DIALS]);
        assert!(!park_automatic_dial(&mut parked, duplicate, &book, &active));
        assert!(book.is_pending(address), "overflow preserves active owner");
        assert_eq!(book.is_feeler(address), feeler);
        let worker_book = Arc::clone(&book);
        handles.push((
            address,
            thread::spawn(move || {
                assert!(
                    worker_book.is_pending(address),
                    "claim remains through worker teardown"
                );
                Ok(())
            }),
        ));
        finish_outbound_epoch(parked, &active, handles, &book);
        assert!(!book.is_pending(address));
        assert!(
            book.take_restart_anchors(10_002).is_empty(),
            "dispatched anchor is never returned"
        );
    }
}

#[test]
fn rejected_anchor_returns_original_metadata_and_releases_its_asmap_group() {
    let (mut maintenance, queue) = maintenance_fixture(1);
    let directory = tempfile::tempdir().expect("directory");
    let map = directory.path().join("asmap.raw");
    std::fs::write(
        &map,
        include_bytes!("../../tests/data/asmap-source-quota-core-v31.1.raw"),
    )
    .expect("map");
    let base = directory.path().join("peers.dat");
    let path = directory.path().join("peers-01010101.dat");
    let book = crate::addrman::AddressBook::open(Some(base), [1; 4], false, Some(&map));
    maintenance.address_book = Arc::clone(&book);
    let anchor: PeerEndpoint = "8.8.0.1:8333".parse::<PeerEndpoint>().expect("anchor");
    let same_as: PeerEndpoint = "9.9.0.1:8333".parse::<PeerEndpoint>().expect("same ASN");
    book.learn_dns("seed", &[anchor], 10_000);
    book.succeeded(anchor, 9, 10_000);
    book.learn_dns("seed", &[same_as], 10_000);
    assert_eq!(
        book.select(&[], &[], 10_000, u64::MAX, |addr| addr == same_as),
        Some(same_as)
    );
    book.remember_anchors(&[anchor], 10_000);
    let mut anchors = book.take_restart_anchors(10_001).into();
    assert_eq!(
        book.select(&[], &[], 10_001, u64::MAX, |addr| addr == same_as),
        None
    );
    maintenance.banned = BannedReader::new(Arc::new(RwLock::new(vec![crate::BannedSubnet {
        subnet: "8.8.0.1/32".parse().expect("anchor ban"),
        banned_until: None,
        ban_created: SystemTime::now(),
        reason: String::new(),
    }])));
    queue_restart_anchors(
        &maintenance,
        &mut anchors,
        &mut None,
        &mut Vec::new(),
        10_002,
    );
    assert!(queue.try_recv().is_err());
    assert!(!book.is_pending(anchor));
    assert_eq!(
        book.select(&[], &[], 10_002, u64::MAX, |addr| addr == same_as),
        Some(same_as)
    );
    assert_eq!(saved_book(&path)["anchors"][0]["confirmed_at"], 10_000);
    assert_eq!(book.take_restart_anchors(10_003), vec![anchor]);
}

#[test]
fn inactive_boot_preserves_anchors_and_shutdown_returns_queued_undispatched_payload() {
    let (mut maintenance, queue) = maintenance_fixture(1);
    let directory = tempfile::tempdir().expect("directory");
    let base = directory.path().join("peers.dat");
    let path = directory.path().join("peers-01010101.dat");
    let book = crate::addrman::AddressBook::open(Some(base), [1; 4], false, None);
    maintenance.address_book = Arc::clone(&book);
    maintenance.network_active.store(false, Ordering::Release);
    let address: PeerEndpoint = "8.8.8.8:8333".parse().expect("address");
    let now = crate::addrman::now();
    book.learn_dns("seed", &[address], now);
    book.succeeded(address, 9, now);
    book.remember_anchors(&[address], now);
    book.save();
    let original = std::fs::read(&path).expect("original");
    let maintenance = Arc::new(maintenance);
    let worker_maintenance = Arc::clone(&maintenance);
    let worker = thread::spawn(move || run_address_maintenance(&worker_maintenance));
    assert!(queue.recv_timeout(Duration::from_millis(250)).is_err());
    assert!(!book.is_pending(address));
    assert_eq!(std::fs::read(&path).expect("inactive book"), original);
    maintenance.network_active.store(true, Ordering::Release);
    let queued = queue
        .recv_timeout(Duration::from_secs(3))
        .expect("first active anchor");
    assert_eq!(queued.addr, address);
    assert_eq!(queued.purpose, DialPurpose::Anchor);
    assert!(book.is_pending(address));
    maintenance.shutdown.store(true, Ordering::Release);
    worker.join().expect("maintenance shutdown");
    assert!(!book.is_pending(address));
    assert!(
        !book.anchor_dispatched(address),
        "stale queued endpoint cannot dispatch after return"
    );
    assert_eq!(saved_book(&path)["anchors"][0]["confirmed_at"], now);
    assert_eq!(book.take_restart_anchors(now), vec![address]);
}
struct ServiceTip {
    time: std::sync::atomic::AtomicU32,
    pause: Mutex<Option<(Sender<()>, Receiver<()>)>>,
}
impl crate::ChainQuery for ServiceTip {
    fn stale_tip_announcement(
        &self,
        _: bitcoin_rs_primitives::Hash256,
        _: &[bitcoin_rs_primitives::Hash256],
    ) -> Option<crate::dispatch::StaleTipHeaders> {
        None
    }
    fn headers_after(
        &self,
        _: &[bitcoin_rs_primitives::BlockHash],
        _: bitcoin_rs_primitives::BlockHash,
        _: usize,
    ) -> Vec<bitcoin_rs_primitives::Header> {
        Vec::new()
    }
    fn serve_inventory_blocks(
        &self,
        _: &[bitcoin::p2p::message_blockdata::Inventory],
        _: Option<u64>,
        _: &dyn Fn() -> bool,
        _: &mut dyn FnMut(crate::Message) -> Result<(), crate::PeerError>,
    ) -> Result<crate::dispatch::InventoryServing, crate::PeerError> {
        Ok(crate::dispatch::InventoryServing::default())
    }
    fn block_transactions(
        &self,
        _: &bitcoin::bip152::BlockTransactionsRequest,
        _: Option<u64>,
        _: &dyn Fn() -> bool,
    ) -> Result<Option<crate::Message>, crate::PeerError> {
        Ok(None)
    }
    fn best_block_time(&self) -> Option<u32> {
        let pause = self.pause.lock().take();
        if let Some((entered, release)) = pause {
            entered.send(()).expect("query entered");
            release
                .recv_timeout(Duration::from_secs(5))
                .expect("release query");
        }
        Some(self.time.load(Ordering::Acquire))
    }
}

#[test]
fn ordinary_queue_rechecks_services_and_tip_before_dispatch_and_tcp() {
    for tip_changes in [false, true] {
        let server = TcpListener::bind("127.0.0.1:0").expect("listener");
        server.set_nonblocking(true).expect("nonblocking");
        let address = server.local_addr().expect("address");
        let now = crate::addrman::now();
        let tip = Arc::new(ServiceTip {
            time: std::sync::atomic::AtomicU32::new(
                u32::try_from(now - 143 * 600).expect("tip time"),
            ),
            pause: Mutex::new(None),
        });
        let query: Arc<dyn crate::ChainQuery> = tip.clone();
        let book = crate::addrman::AddressBook::open(None, [1; 4], true, None);
        book.learn_dns("seed", &[address.into()], now);
        book.succeeded(address.into(), if tip_changes { 1032 } else { 9 }, now);
        let (mut maintenance, queue) = maintenance_fixture(1);
        maintenance.address_book = Arc::clone(&book);
        maintenance.chain_query = Some(Arc::clone(&query));
        queue_address_candidates(&maintenance, now, SystemTime::now(), 0);
        let candidate = queue.try_recv().expect("eligible candidate is queued");
        let mut parked = VecDeque::new();
        assert!(park_automatic_dial(
            &mut parked,
            candidate,
            &book,
            &HashMap::new()
        ));
        if tip_changes {
            tip.time.store(
                u32::try_from(now - 144 * 600).expect("older tip"),
                Ordering::Release,
            );
        } else {
            book.set_services(address.into(), 1);
        }
        let mut shared = crate::listener::ConnectionShared::new(
            Arc::clone(&maintenance.peer_table),
            BannedReader::fixture_empty(),
            Arc::new(crate::NetworkActivity::from_shared(Arc::new(
                AtomicBool::new(true),
            ))),
            Arc::new(AtomicBool::new(false)),
            None,
            Magic::REGTEST,
            crossbeam_channel::bounded(1).0,
            crossbeam_channel::bounded(1).0,
            Some(query),
            None,
            crate::listener::ListenerExtras::default(),
        );
        shared.address_book = Some(Arc::clone(&book));
        let mut active = HashMap::new();
        let mut handles = Vec::new();
        spawn_outbound_dial(
            &parked.pop_front().expect("parked dial"),
            &shared,
            &mut active,
            &mut handles,
            1,
            0,
            false,
            125,
        );
        assert_eq!(
            handles.len(),
            0,
            "stale parked metadata never starts a worker"
        );
        assert!(
            !book.is_pending(address.into()),
            "rejected ordinary claim is released"
        );
        let result = crate::listener::spawn_outbound_connection(
            address.into(),
            shared,
            crate::PeerRole::FullRelay,
        )
        .join()
        .expect("thread");
        assert!(
            matches!(
                result,
                Err(crate::PeerError::Protocol(
                    "outbound peer lacks desirable services"
                ))
            ),
            "final listener admission must independently recheck"
        );
        assert!(
            matches!(server.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "no TCP connection reached the listener"
        );
    }
}

#[test]
fn ordinary_selection_skips_known_incomplete_peer_and_anchor_return_preserves_age() {
    let (mut maintenance, queue) = maintenance_fixture(1);
    let directory = tempfile::tempdir().expect("directory");
    let book = crate::addrman::AddressBook::open(
        Some(directory.path().join("peers.dat")),
        [1; 4],
        false,
        None,
    );
    maintenance.address_book = Arc::clone(&book);
    let bad: PeerEndpoint = "8.8.8.8:8333".parse().expect("incomplete");
    let healthy: PeerEndpoint = "9.9.9.9:8333".parse().expect("healthy");
    book.learn_dns("seed", &[bad, healthy], 10_000);
    book.succeeded(bad, 9, 10_000);
    book.succeeded(healthy, 9, 10_000);
    book.remember_anchors(&[bad], 10_000);
    let mut anchors = book.take_restart_anchors(10_001).into();
    book.set_services(bad, 1);
    queue_restart_anchors(
        &maintenance,
        &mut anchors,
        &mut None,
        &mut Vec::new(),
        10_002,
    );
    assert!(queue.try_recv().is_err());
    assert!(!book.is_pending(bad));
    assert_eq!(
        saved_book(&directory.path().join("peers-01010101.dat"))["anchors"][0]["confirmed_at"],
        10_000
    );
    queue_address_candidates(
        &maintenance,
        10_002,
        SystemTime::UNIX_EPOCH + Duration::from_secs(10_002),
        0,
    );
    assert_eq!(
        queue.try_recv().expect("healthy ordinary candidate").addr,
        healthy
    );
}
#[test]
fn disable_during_outbound_tip_query_refuses_registration_before_handshake() {
    let directory = tempfile::tempdir().expect("directory");
    let service = Arc::new(P2pService::new(
        P2pServiceConfig {
            address_book_path: Some(directory.path().join("peers.dat")),
            allow_local_addresses: true,
            dns_seeds_enabled: false,
            magic: Magic::REGTEST,
            ..P2pServiceConfig::default()
        },
        Arc::new(AtomicBool::new(false)),
    ));
    let server = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = server.local_addr().expect("address");
    let now = crate::addrman::now();
    service
        .address_book
        .learn_dns("loopback", &[address.into()], now);
    service.address_book.set_services(address.into(), 9);
    let (entered, entered_rx) = crossbeam_channel::bounded(1);
    let (release, release_rx) = crossbeam_channel::bounded(1);
    let query: Arc<dyn crate::ChainQuery> = Arc::new(ServiceTip {
        time: std::sync::atomic::AtomicU32::new(u32::try_from(now).expect("tip time")),
        pause: Mutex::new(Some((entered, release_rx))),
    });
    let ready = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ready_count = Arc::clone(&ready);
    let mut shared = crate::listener::ConnectionShared::new(
        Arc::clone(&service.peer_table),
        service.banned_reader(),
        Arc::new(crate::NetworkActivity::from_shared(Arc::clone(
            &service.network_active,
        ))),
        Arc::clone(&service.session_cancel.lock()),
        Some(Arc::new(move |_| {
            ready_count.fetch_add(1, Ordering::Relaxed);
        })),
        Magic::REGTEST,
        crossbeam_channel::bounded(1).0,
        crossbeam_channel::bounded(1).0,
        Some(query),
        None,
        crate::listener::ListenerExtras::default(),
    );
    shared.address_book = Some(Arc::clone(&service.address_book));
    let worker = crate::listener::spawn_outbound_connection(
        address.into(),
        shared,
        crate::PeerRole::FullRelay,
    );
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("passed early activity check, paused before TCP");
    let disabling_service = Arc::clone(&service);
    let (disabled_tx, disabled_rx) = crossbeam_channel::bounded(1);
    let disable = thread::spawn(move || {
        disabling_service.set_network_active(false);
        disabled_tx.send(()).expect("disabled");
    });
    let disabled = disabled_rx.recv_timeout(Duration::from_secs(5));
    release.send(()).expect("release metadata query");
    disable.join().expect("disable worker");
    let (mut remote, _) = server.accept().expect("TCP can complete after disable");
    remote
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut byte = [0];
    let received = std::io::Read::read(&mut remote, &mut byte);
    let _ = remote.shutdown(std::net::Shutdown::Both);
    drop(remote);
    let result = worker.join().expect("outbound worker");
    disabled.expect("disable does not wait for socket I/O or metadata query");
    assert_eq!(received.expect("closed without handshake"), 0);
    assert!(
        matches!(
            result,
            Err(crate::PeerError::Protocol(
                "transport or network unavailable"
            ))
        ),
        "unexpected outbound result: {result:?}"
    );
    assert_eq!(service.peer_table.sessions().len(), 0);
    assert_eq!(ready.load(Ordering::Relaxed), 0);
    service.address_book.save();
    let record = &saved_book(&directory.path().join("peers-fabfb5da.dat"))["records"][0];
    assert_eq!(record["last_success"], 0);
    assert_eq!(record["tried"], false);
}

#[test]
fn workers_teardown_cleans_resources_and_cancels_sessions() {
    let peer_table = Arc::new(crate::PeerTable::new());
    let addresses = Mutex::new(vec![crate::PeerEndpoint::Ip(SocketAddr::from((
        [127, 0, 0, 1],
        8333,
    )))]);
    let shutdown = Arc::new(AtomicBool::new(false));
    let session_cancel = Arc::new(AtomicBool::new(false));
    let mut workers = Workers::new(Arc::clone(&shutdown), Arc::clone(&session_cancel));

    let thread_shutdown = Arc::clone(&shutdown);
    let handle = thread::spawn(move || {
        while !thread_shutdown.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    });
    workers.listeners.push(handle);

    assert!(!shutdown.load(Ordering::Acquire));
    assert!(!session_cancel.load(Ordering::Acquire));
    assert!(!addresses.lock().is_empty());

    workers.teardown(&peer_table, &addresses);

    assert!(shutdown.load(Ordering::Acquire));
    assert!(session_cancel.load(Ordering::Acquire));
    assert!(addresses.lock().is_empty());
    assert!(workers.listeners.is_empty());
}

#[test]
fn bootstrap_fixed_peer_endpoints_valid_typed_endpoints_bypass_resolver() {
    let network_active = AtomicBool::new(true);
    let peer_table = crate::PeerTable::new();
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();

    let good_tor_payload = bitcoin_rs_primitives::endpoint::tor_v3_payload(&[7u8; 32]);
    let valid_onion = format!(
        "{}.onion:8333",
        bitcoin_rs_primitives::endpoint::base32_encode(&good_tor_payload)
    );
    let valid_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

    let mut resolve_calls = 0;
    let valid_overlay_targets = vec![valid_onion, valid_i2p];
    bootstrap_fixed_peer_endpoints(
        &network_active,
        &peer_table,
        &outbound_tx,
        &valid_overlay_targets,
        |_host| {
            resolve_calls += 1;
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], 8333))])
        },
    );
    assert_eq!(
        resolve_calls, 0,
        "injected resolver must remain untouched for valid overlay targets"
    );
    assert!(matches!(
        outbound_rx.try_recv().expect("valid onion dial").addr,
        crate::PeerEndpoint::TorV3 { .. }
    ));
    assert!(matches!(
        outbound_rx.try_recv().expect("valid i2p dial").addr,
        crate::PeerEndpoint::I2p { .. }
    ));

    bootstrap_fixed_peer_endpoints(
        &network_active,
        &peer_table,
        &outbound_tx,
        &["127.0.0.1:8333".to_owned()],
        |_host| {
            resolve_calls += 1;
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], 8333))])
        },
    );
    assert_eq!(
        resolve_calls, 0,
        "injected resolver must remain untouched for direct IP"
    );
    assert_eq!(
        outbound_rx.try_recv().expect("direct ip dial").addr,
        crate::PeerEndpoint::Ip(SocketAddr::from(([127, 0, 0, 1], 8333)))
    );
}

fn malformed_reserved_overlay_targets_testdata() -> Vec<String> {
    let good_tor_payload = bitcoin_rs_primitives::endpoint::tor_v3_payload(&[7u8; 32]);
    let valid_onion = format!(
        "{}.onion:8333",
        bitcoin_rs_primitives::endpoint::base32_encode(&good_tor_payload)
    );
    let valid_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

    let mut bad_payload = good_tor_payload;
    bad_payload[32] ^= 1;
    let invalid_checksum_onion = format!(
        "{}.onion:8333",
        bitcoin_rs_primitives::endpoint::base32_encode(&bad_payload)
    );
    let good_b32 = bitcoin_rs_primitives::endpoint::base32_encode(&good_tor_payload);

    vec![
        invalid_checksum_onion,
        "abc.onion:8333".to_owned(),
        format!("{}.b32.i2p:8333", "a".repeat(51)),
        format!("{}.b32.i2p:8333", "a".repeat(53)),
        format!("{good_b32}.onion:notaport"),
        format!("{good_b32}.onion:0"),
        format!("{good_b32}.onion:99999"),
        format!("{good_b32}.onion"),
        format!("{}.b32.i2p", "a".repeat(52)),
        valid_onion.to_uppercase(),
        valid_i2p.to_uppercase(),
        format!("{good_b32}.onion.:8333"),
        format!("{good_b32}.onion."),
        format!("{}.b32.i2p.:8333", "a".repeat(52)),
        format!("{}.b32.i2p.", "a".repeat(52)),
        "foo.i2p:8333".to_owned(),
        "foo.i2p".to_owned(),
        "FOO.I2P:8333".to_owned(),
        "foo.I2P:8333".to_owned(),
        "foo.i2p.:8333".to_owned(),
        "foo.i2p.".to_owned(),
        "b32.i2p:8333".to_owned(),
        "b32.i2p".to_owned(),
        "B32.I2P:8333".to_owned(),
        "b32.i2p.:8333".to_owned(),
        "b32.i2p.".to_owned(),
        "onion.:8333".to_owned(),
        "onion.".to_owned(),
        "ONION.:8333".to_owned(),
        "i2p.:8333".to_owned(),
        "i2p.".to_owned(),
        "I2P.:8333".to_owned(),
    ]
}

#[test]
fn bootstrap_fixed_peer_endpoints_malformed_reserved_overlay_names_bypass_resolver() {
    let network_active = AtomicBool::new(true);
    let peer_table = crate::PeerTable::new();
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();

    let rejected_overlay_targets = malformed_reserved_overlay_targets_testdata();

    let mut resolve_calls = 0;
    bootstrap_fixed_peer_endpoints(
        &network_active,
        &peer_table,
        &outbound_tx,
        &rejected_overlay_targets,
        |_host| {
            resolve_calls += 1;
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], 8333))])
        },
    );
    assert_eq!(
        resolve_calls, 0,
        "injected resolver must remain untouched for rejected overlay targets"
    );
    assert!(
        outbound_rx.try_recv().is_err(),
        "no dial should be generated for rejected overlay targets"
    );
}

#[test]
fn bootstrap_fixed_peer_endpoints_ordinary_dns_and_lan_use_resolver() {
    let network_active = AtomicBool::new(true);
    let peer_table = crate::PeerTable::new();
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();

    let ordinary_hostnames = vec![
        "seed.bitcoin.sipa.be:8333".to_owned(),
        "fakeb32.i2p.org:8333".to_owned(),
        "onion:8333".to_owned(),
        "i2p:8333".to_owned(),
    ];
    let expected_addr = SocketAddr::from(([192, 0, 2, 42], 8333));
    let mut resolve_calls = 0;
    bootstrap_fixed_peer_endpoints(
        &network_active,
        &peer_table,
        &outbound_tx,
        &ordinary_hostnames,
        |_host| {
            resolve_calls += 1;
            Ok(vec![expected_addr])
        },
    );
    assert_eq!(
        resolve_calls, 4,
        "injected resolver must be called for ordinary DNS and LAN hostnames"
    );
    for _ in 0..4 {
        assert_eq!(
            outbound_rx.try_recv().expect("dns dial").addr,
            crate::PeerEndpoint::Ip(expected_addr)
        );
    }
}

#[test]
fn bootstrap_fixed_peer_endpoints_queue_and_cancellation() {
    let peer_table = crate::PeerTable::new();

    let network_inactive = AtomicBool::new(false);
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
    let mut resolve_calls = 0;
    bootstrap_fixed_peer_endpoints(
        &network_inactive,
        &peer_table,
        &outbound_tx,
        &[
            "seed.bitcoin.sipa.be:8333".to_owned(),
            "127.0.0.1:8333".to_owned(),
        ],
        |_host| {
            resolve_calls += 1;
            Ok(vec![SocketAddr::from(([192, 0, 2, 42], 8333))])
        },
    );
    assert_eq!(resolve_calls, 0);
    assert!(outbound_rx.try_recv().is_err());

    let network_active = AtomicBool::new(true);
    let (bounded_tx, bounded_rx) = crossbeam_channel::bounded(1);
    bootstrap_fixed_peer_endpoints(
        &network_active,
        &peer_table,
        &bounded_tx,
        &["127.0.0.1:8333".to_owned(), "127.0.0.2:8333".to_owned()],
        |_host| Ok(vec![SocketAddr::from(([127, 0, 0, 1], 8333))]),
    );
    assert!(bounded_rx.try_recv().is_ok());
    assert!(bounded_rx.try_recv().is_err());
}
