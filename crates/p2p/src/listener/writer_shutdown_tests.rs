use bitcoin_rs_primitives::PeerEndpoint;
use std::cell::Cell;
use std::io;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use bitcoin::p2p::Magic;

use super::{
    collect_write_burst, run_connected_session, run_message_loop, run_writer_loop,
    spawn_connection_writer, test_shared,
};
use crate::connection::OutboundBudget;
use crate::peer::{Peer, PeerState};

const FAILSAFE: Duration = Duration::from_secs(5);

#[test]
fn inbound_handshake_failure_on_live_lease_returns_err() {
    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let shared = test_shared(
        Arc::new(crate::PeerTable::new()),
        headers_tx,
        crossbeam_channel::unbounded().0,
    );
    let (mut client, server, peer_addr) = loopback_pair();

    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33]);
    frame.extend_from_slice(b"version\0\0\0\0\0");
    frame.extend_from_slice(&0_u32.to_le_bytes());
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    io::Write::write_all(&mut client, &frame).expect("frame write");
    drop(client);

    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new_inbound(outbound_tx);
    let lease = shared
        .peer_table
        .try_register_inbound(peer_addr, lease, &[], 1, 0, &shared.activity)
        .expect("the test lease reserves its inbound slot");
    let result = crate::listener::run_handshake(server, peer_addr, &shared, lease, outbound_rx);
    let Err(error) = result else {
        panic!("handshake failure on a live lease must not be masked as revoked");
    };
    assert!(
        error.to_string().contains("magic"),
        "unexpected handshake error: {error}"
    );
}

fn loopback_pair() -> (TcpStream, TcpStream, PeerEndpoint) {
    let listener = TcpListener::bind(
        PeerEndpoint::from((Ipv4Addr::LOCALHOST, 0))
            .socket_addr()
            .unwrap_or_else(|| panic!("expected IP fixture")),
    )
    .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, peer_addr) = listener.accept().expect("accept");
    (client, server, peer_addr.into())
}

fn ping_len() -> usize {
    crate::wire::wire_len(&crate::Message::Ping(9)).expect("ping encodes")
}

#[test]
fn unbacked_filter_service_bit_is_removed_from_handshake() {
    let mut shared = test_shared(
        Arc::new(crate::PeerTable::new()),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    );
    shared.local_services |= bitcoin::p2p::ServiceFlags::COMPACT_FILTERS;
    assert!(
        !shared
            .advertised_services()
            .has(bitcoin::p2p::ServiceFlags::COMPACT_FILTERS)
    );
}

fn peer_info(addr: PeerEndpoint, start_height: i32) -> crate::PeerInfo {
    crate::PeerInfo {
        endpoint: Some(addr),
        network: addr.net(),
        addr: addr.into(),
        version: 70_016,
        wtxid_relay: false,
        relay_transactions: true,
        compact_block_relay: false,
        send_headers: false,
        services: 1,
        user_agent: String::from("/test/"),
        start_height,
        conn_time: 0,
        best_known_height: start_height,
        inbound: false,
        addr_bind: crate::TransportRemote::new(
            addr.socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
        ),
        time_offset: 0,
        counters: std::sync::Arc::new(crate::PeerCounters::default()),
        transport: crate::TransportProtocol::V1,
    }
}

#[test]
fn sinks_stamp_exact_connection_source() -> Result<(), Box<dyn std::error::Error>> {
    let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
    let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_443));
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let block_bytes = bitcoin::consensus::encode::serialize(&genesis);
    let serialized = bytes::Bytes::from(block_bytes);
    let payload = bitcoin_rs_primitives::BlockPayload::from_raw(serialized.clone())
        .map_err(|_| std::io::Error::other("genesis block must decode"))?;
    let source = lease.source(Some(addr));

    shared.send_headers(&lease, source, Vec::new(), true);
    shared.send_block(&lease, addr, payload);

    assert_eq!(headers_rx.try_recv()?.source, Some(source));
    let received = blocks_rx.try_recv()?;
    assert_eq!(received.source, Some(source));
    assert_eq!(received.payload().bytes(), &serialized);
    Ok(())
}

#[test]
fn send_block_forwards_the_blocks_header() -> Result<(), Box<dyn std::error::Error>> {
    let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
    let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_449));
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let block_bytes = bitcoin::consensus::encode::serialize(&genesis);
    let payload = bitcoin_rs_primitives::BlockPayload::from_raw(bytes::Bytes::from(block_bytes))
        .map_err(|_| std::io::Error::other("genesis block must decode"))?;
    let header = payload.block().header;
    let source = lease.source(Some(addr));

    shared.send_block(&lease, addr, payload);

    let forwarded = headers_rx.try_recv()?;
    assert_eq!(forwarded.source, Some(source));
    assert_eq!(forwarded.headers, vec![header]);
    assert!(
        !forwarded.wire_response,
        "a body-carried header is not a getheaders response"
    );
    Ok(())
}

#[test]
fn send_block_unblocks_when_session_is_cancelled() -> Result<(), Box<dyn std::error::Error>> {
    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(1);
    let shared = test_shared(Arc::new(crate::PeerTable::new()), headers_tx, blocks_tx);
    let session_cancel = shared.session_cancel.clone();
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_448));
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let first_bytes = bitcoin::consensus::encode::serialize(&genesis);
    let first = bitcoin_rs_primitives::BlockPayload::from_raw(bytes::Bytes::from(first_bytes))
        .map_err(|_| std::io::Error::other("genesis block must decode"))?;
    let second_bytes = first.bytes().clone();
    let second = bitcoin_rs_primitives::BlockPayload::from_raw(second_bytes)
        .map_err(|_| std::io::Error::other("genesis block must decode"))?;
    shared.send_block(&lease, addr, first);

    let blocked = std::thread::spawn(move || {
        shared.send_block(&lease, addr, second);
    });
    let started = std::time::Instant::now();
    while !blocked.is_finished() && started.elapsed() < Duration::from_millis(250) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !blocked.is_finished(),
        "full inbound block channel must block until cancel"
    );
    session_cancel.store(true);
    blocked
        .join()
        .map_err(|_| std::io::Error::other("send_block thread panicked"))?;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "cancelled send_block must not wait on the full queue"
    );
    drop(blocks_rx);
    Ok(())
}

#[test]
fn message_loop_exits_before_read_when_cancelled() {
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_444));
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    lease.cancel();
    let mut peer = Peer::new(
        ScriptedStream {
            script: io::Cursor::new(Vec::new()),
        },
        Magic::BITCOIN,
    );
    peer.state = PeerState::Ready;

    let shared = test_shared(
        Arc::new(crate::PeerTable::new()),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    );
    assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_ok());
}

#[test]
fn message_loop_exits_after_replacement_during_read() {
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_445));
    let table = Arc::new(crate::PeerTable::new());
    let (old_tx, _old_rx) = crossbeam_channel::unbounded();
    let old = crate::PeerLease::new(old_tx);
    table.register(addr, old.clone());
    let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
    let replacement = crate::PeerLease::new(replacement_tx);
    table.register(addr, replacement.clone());

    let mut wire = Vec::new();
    crate::wire::write_message(
        &mut wire,
        Magic::BITCOIN,
        &crate::Message::Headers(Vec::new()),
    )
    .expect("headers encodes");
    let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
    let shared = test_shared(
        Arc::clone(&table),
        headers_tx,
        crossbeam_channel::unbounded().0,
    );
    let mut peer = Peer::new(
        ScriptedStream {
            script: io::Cursor::new(wire),
        },
        Magic::BITCOIN,
    );
    peer.state = PeerState::Ready;

    assert!(run_message_loop(&mut peer, addr, &old, &shared, None).is_ok());
    assert!(headers_rx.try_recv().is_err());
    assert!(old.is_cancelled());
    assert!(table.is_current(replacement.source(Some(addr))));
}

fn sendcmpct_scenario(send_compact: bool, version: u64, port: u16) -> bool {
    let mut wire = Vec::new();
    crate::wire::write_message(
        &mut wire,
        Magic::BITCOIN,
        &crate::Message::SendCmpct(bitcoin::p2p::message_compact_blocks::SendCmpct {
            send_compact,
            version,
        }),
    )
    .expect("sendcmpct encodes");
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, port));
    let table = Arc::new(crate::PeerTable::new());
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    table.register(addr, lease.clone());
    assert!(
        table.publish_info(
            addr,
            &lease,
            crate::PeerInfo {
                endpoint: Some(addr),
                network: addr.net(),
                addr: addr.into(),
                version: 70_016,
                wtxid_relay: false,
                relay_transactions: true,
                compact_block_relay: false,
                send_headers: false,
                services: 0,
                user_agent: String::from("/test/"),
                start_height: 0,
                best_known_height: 0,
                conn_time: 0,
                inbound: false,
                addr_bind: crate::TransportRemote::new(
                    addr.socket_addr()
                        .unwrap_or_else(|| panic!("expected IP fixture")),
                ),
                time_offset: 0,
                counters: std::sync::Arc::new(crate::PeerCounters::default()),
                transport: crate::TransportProtocol::V1,
            },
        )
    );
    let mut peer = Peer::new(ScriptedEof(io::Cursor::new(wire)), Magic::BITCOIN);
    peer.state = PeerState::Ready;
    let shared = test_shared(
        Arc::clone(&table),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    );
    assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_err());
    table.compact_relay_of(addr)
}

#[test]
fn sendcmpct_raises_published_compact_relay_preference() {
    assert!(sendcmpct_scenario(true, 2, 18_448));
    assert!(sendcmpct_scenario(false, 2, 18_449));
    assert!(!sendcmpct_scenario(false, 1, 18_450));
    assert!(!sendcmpct_scenario(false, 7, 18_451));
}

struct ScriptedEof(io::Cursor<Vec<u8>>);

impl io::Read for ScriptedEof {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match io::Read::read(&mut self.0, buf)? {
            0 => Err(io::ErrorKind::UnexpectedEof.into()),
            read => Ok(read),
        }
    }
}

impl io::Write for ScriptedEof {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ContinuingStream(Arc<AtomicUsize>);

impl io::Read for ContinuingStream {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }
}

impl io::Write for ContinuingStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn message_loop_keeps_current_lease_running() {
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_446));
    let reads = Arc::new(AtomicUsize::new(0));
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    let mut peer = Peer::new(ContinuingStream(Arc::clone(&reads)), Magic::BITCOIN);
    peer.state = PeerState::Ready;
    let shared = test_shared(
        Arc::new(crate::PeerTable::new()),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    );

    assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_err());
    assert_eq!(reads.load(Ordering::Relaxed), 2);
}

#[test]
fn message_loop_does_not_probe_a_peer_inside_one_interval() {
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(outbound_tx);
    let reads = Arc::new(AtomicUsize::new(0));
    let mut peer = Peer::new(ContinuingStream(Arc::clone(&reads)), Magic::BITCOIN);
    peer.state = PeerState::Ready;
    let shared = test_shared(
        Arc::new(crate::PeerTable::new()),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    );
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_448));

    assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_err());
    assert!(
        matches!(
            outbound_rx.try_recv(),
            Err(crossbeam_channel::TryRecvError::Empty)
        ),
        "a peer quiet for less than one interval owes no probe",
    );
}

#[test]
fn registration_cancels_replaced_lease() {
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_447));
    let table = crate::PeerTable::new();
    let (old_tx, _old_rx) = crossbeam_channel::unbounded();
    let old = crate::PeerLease::new(old_tx);
    table.register(addr, old.clone());
    let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
    let replacement = crate::PeerLease::new(replacement_tx);

    assert!(table.register(addr, replacement.clone()));
    table.publish_info(addr, &replacement, peer_info(addr, 2));
    assert!(old.is_cancelled());
    assert!(table.is_current(replacement.source(Some(addr))));
    assert_eq!(table.infos(), vec![peer_info(addr, 2)]);
}

#[test]
fn stale_release_preserves_replacement_and_current_release_removes_it() {
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_448));
    let table = crate::PeerTable::new();
    let (stale_tx, _stale_rx) = crossbeam_channel::unbounded();
    let stale = crate::PeerLease::new(stale_tx);
    let (current_tx, _current_rx) = crossbeam_channel::unbounded();
    let current = crate::PeerLease::new(current_tx);
    table.register(addr, current.clone());
    table.publish_info(addr, &current, peer_info(addr, 2));

    assert!(!table.remove_current(addr, &stale));
    assert!(!current.is_cancelled());
    assert!(table.is_current(current.source(Some(addr))));
    assert!(table.remove_current(addr, &current));
    assert!(current.is_cancelled());
    assert!(table.is_empty());
}

struct BlockingTestWriter {
    remaining: Cell<usize>,
    unblock: crossbeam_channel::Receiver<()>,
    blocked: crossbeam_channel::Sender<()>,
}

impl io::Write for BlockingTestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self.remaining.get();
        if buf.len() <= remaining {
            self.remaining.set(remaining - buf.len());
            Ok(buf.len())
        } else {
            let _ = self.blocked.try_send(());
            let _ = self.unblock.recv();
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "test: unblocked",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct EventWriter {
    events: crossbeam_channel::Sender<()>,
}

impl io::Write for EventWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.events.send(());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ScriptedStream {
    script: io::Cursor<Vec<u8>>,
}

impl io::Read for ScriptedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match io::Read::read(&mut self.script, buf)? {
            0 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            read => Ok(read),
        }
    }
}

impl io::Write for ScriptedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn cancel_wakes_writer_blocked_on_empty_queue_with_live_senders() {
    let (_client, server, peer_addr) = loopback_pair();
    let writer_stream = crate::CountingStream::new(
        server.try_clone().expect("try_clone"),
        std::sync::Arc::new(crate::PeerCounters::default()),
    );
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(outbound_tx);
    let lease_probe = lease.clone();

    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let writer = spawn_connection_writer(
        writer_stream,
        crate::transport::SendTransport::V1(Magic::BITCOIN),
        outbound_rx,
        lease.close_signal(),
        lease.budget_handle(),
        peer_addr,
        None,
    )
    .expect("spawn writer");
    let waiter = std::thread::spawn(move || {
        writer.join().expect("writer join");
        let _ = done_tx.send(());
    });

    lease.cancel();
    done_rx
        .recv_timeout(FAILSAFE)
        .expect("close signal must wake an idle writer with live senders");
    waiter.join().expect("waiter join");
    assert!(lease_probe.is_cancelled());
}

#[test]
fn writer_mid_write_exits_on_unblock_deterministically() {
    let frame = ping_len();
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new_with_budget(
        outbound_tx,
        false,
        OutboundBudget::with_block_reserve(100, 100 * frame, 0),
    );

    for _ in 0..5 {
        lease
            .send(crate::Message::Ping(9))
            .expect("fresh queue admits a ping");
    }
    assert_eq!(lease.budget_handle().pending(), (5, 5 * frame));

    let (unblock_tx, unblock_rx) = crossbeam_channel::bounded(1);
    let (blocked_tx, blocked_rx) = crossbeam_channel::bounded(1);
    let mut writer = BlockingTestWriter {
        remaining: Cell::new(2 * frame),
        unblock: unblock_rx,
        blocked: blocked_tx,
    };
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let close_rx = lease.close_signal();
    let net_trace = crate::net_trace::NetTrace::outbound(
        9,
        "127.0.0.1:18444".parse().expect("valid socket address"),
        crate::peer_info::PeerRole::BlockRelayOnly,
        false,
    );
    let worker = std::thread::spawn(move || {
        run_writer_loop(
            &outbound_rx,
            close_rx,
            &mut writer,
            &mut crate::transport::SendTransport::V1(Magic::BITCOIN),
            Some(&net_trace),
        );
        let _ = done_tx.send(());
    });

    blocked_rx
        .recv_timeout(FAILSAFE)
        .expect("writer must exhaust its byte budget");
    assert_eq!(
        lease.budget_handle().pending(),
        (5, 5 * frame),
        "a burst in flight keeps its charge"
    );

    lease.cancel();
    let _ = unblock_tx.send(());
    done_rx
        .recv_timeout(FAILSAFE)
        .expect("unblock must release the blocked writer");
    worker.join().expect("worker join");

    assert_eq!(
        lease.budget_handle().pending(),
        (0, 0),
        "a failed write drops its burst, and each frame returns its own charge"
    );
}

#[test]
fn writer_releases_budget_after_write() {
    let frame = ping_len();
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new_with_budget(
        outbound_tx,
        false,
        OutboundBudget::with_block_reserve(100, 100 * frame, 0),
    );
    lease
        .send(crate::Message::Ping(9))
        .expect("fresh queue admits a ping");
    assert_eq!(lease.budget_handle().pending(), (1, frame));

    let (event_tx, event_rx) = crossbeam_channel::unbounded();
    let mut writer = EventWriter { events: event_tx };
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let budget = lease.budget_handle();
    let close_rx = lease.close_signal();
    let worker = std::thread::spawn(move || {
        run_writer_loop(
            &outbound_rx,
            close_rx,
            &mut writer,
            &mut crate::transport::SendTransport::V1(Magic::BITCOIN),
            None,
        );
        let _ = done_tx.send(());
    });

    drop(lease);

    event_rx
        .recv_timeout(FAILSAFE)
        .expect("writer must emit an event after write returns");
    done_rx
        .recv_timeout(FAILSAFE)
        .expect("writer must exit after senders drop");
    worker.join().expect("worker join");

    assert_eq!(
        budget.pending(),
        (0, 0),
        "written bytes must be fully released"
    );
}

#[test]
fn writer_exit_shuts_down_the_reader_socket_clone() {
    let (mut client, server, peer_addr) = loopback_pair();
    let reader_stream = server.try_clone().expect("reader clone");
    client.set_nonblocking(true).expect("nonblocking client");
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(outbound_tx);
    let writer = spawn_connection_writer(
        crate::CountingStream::new(server, std::sync::Arc::new(crate::PeerCounters::default())),
        crate::transport::SendTransport::V1(Magic::BITCOIN),
        outbound_rx,
        lease.close_signal(),
        lease.budget_handle(),
        peer_addr,
        None,
    )
    .expect("spawn writer");

    lease.cancel();
    writer.join().expect("writer join");

    let mut byte = [0_u8; 1];
    assert_eq!(
        io::Read::read(&mut client, &mut byte).expect("shutdown must produce EOF"),
        0
    );
    drop(reader_stream);
}

#[test]
fn run_connected_session_publishes_peer_relay_preference_and_joins_writer() {
    for peer_requested_wtxid in [false, true] {
        let (client, server, peer_addr) = loopback_pair();
        drop(client);

        let peer_table = Arc::new(crate::PeerTable::new());
        let (published_tx, published_rx) = crossbeam_channel::bounded(1);
        let observed_table = Arc::clone(&peer_table);
        let mut shared = test_shared(
            peer_table,
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        shared.peer_ready = Some(Arc::new(move |_source| {
            let requested = observed_table.infos()[0].wtxid_relay;
            let _ = published_tx.try_send(requested);
        }));

        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        let lease_probe = lease.clone();
        shared.peer_table.register(peer_addr, lease.clone());

        let info = crate::PeerInfo {
            endpoint: Some(peer_addr),
            network: peer_addr.net(),
            addr: crate::PeerRemote::Endpoint(peer_addr),
            version: 70_016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 0,
            user_agent: String::from("/test/"),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: crate::TransportRemote::new(
                peer_addr
                    .socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            ),
            time_offset: 0,
            counters: std::sync::Arc::new(crate::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
        };

        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            let mut peer = Peer::new(
                crate::CountingStream::new(
                    server,
                    std::sync::Arc::new(crate::PeerCounters::default()),
                ),
                Magic::BITCOIN,
            );
            if peer_requested_wtxid {
                peer.wtxid_relay.mark_peer_supported();
            }
            let result =
                run_connected_session(&mut peer, peer_addr, &shared, lease, outbound_rx, info);
            let _ = done_tx.send(result);
        });

        let result = done_rx
            .recv_timeout(FAILSAFE)
            .expect("session must return while an external lease clone is alive");
        worker.join().expect("worker join");
        assert!(result.is_err(), "EOF on read must end the session");
        assert!(lease_probe.is_cancelled());
        assert_eq!(
            published_rx.try_recv().expect("published ready metadata"),
            peer_requested_wtxid
        );
    }
}

#[test]
fn session_disconnect_updates_full_relay_and_preserves_block_relay_privacy() {
    for (block_relay, stale) in [(false, false), (true, false), (false, true)] {
        let (client, server, peer_addr) = loopback_pair();
        drop(client);

        let peer_table = Arc::new(crate::PeerTable::new());
        let mut shared = test_shared(
            peer_table,
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        let book = crate::addrman::AddressBook::open(None, shared.magic.to_bytes(), true, None);
        book.learn_dns("seed", &[peer_addr], 5000);
        shared.address_book = Some(Arc::clone(&book));

        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = if block_relay {
            crate::PeerLease::new_block_relay(outbound_tx)
        } else {
            crate::PeerLease::new(outbound_tx)
        };
        shared.peer_table.register(peer_addr, lease.clone());
        if stale {
            let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
            assert!(
                shared
                    .peer_table
                    .register(peer_addr, crate::PeerLease::new(replacement_tx),)
            );
        }

        let info = crate::PeerInfo {
            endpoint: Some(peer_addr),
            network: peer_addr.net(),
            addr: crate::PeerRemote::Endpoint(peer_addr),
            version: 70_016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 9,
            user_agent: String::from("/test/"),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: crate::TransportRemote::new(
                peer_addr
                    .socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            ),
            time_offset: 0,
            counters: std::sync::Arc::new(crate::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
        };

        let mut peer = Peer::new(
            crate::CountingStream::new(server, std::sync::Arc::new(crate::PeerCounters::default())),
            Magic::BITCOIN,
        );
        let _ = run_connected_session(&mut peer, peer_addr, &shared, lease, outbound_rx, info);

        let last_seen = book.gossip(10_000)[0].time;
        if block_relay || stale {
            assert_eq!(
                last_seen, 5000,
                "block-relay or rejected ready session must never refresh last_seen"
            );
        } else {
            assert_ne!(
                last_seen, 5000,
                "full-relay disconnect must refresh last_seen"
            );
        }
    }
}

struct RelayDuringInventoryLookup {
    table: Arc<crate::PeerTable>,
    gateway: Arc<bitcoin_rs_mempool::MempoolGateway>,
    lease: crate::PeerLease,
    due: std::time::Instant,
    calls: AtomicUsize,
}

impl crate::TxInventory for RelayDuringInventoryLookup {
    fn have_tx(&self, hash: bitcoin_rs_primitives::Hash256, witness: bool) -> bool {
        use bitcoin::secp256k1::rand::SeedableRng as _;
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::seed_from_u64(1484);
        self.table
            .poll_transaction_relay(&self.gateway, self.due, false, &mut rng);
        self.lease.cancel();
        self.gateway.have_tx(hash, witness)
    }

    fn get_tx(&self, txid: bitcoin_rs_primitives::Txid) -> Option<bitcoin_rs_primitives::Tx> {
        self.gateway.get_tx(txid)
    }

    fn get_tx_by_wtxid(
        &self,
        wtxid: bitcoin_rs_primitives::Wtxid,
    ) -> Option<bitcoin_rs_primitives::Tx> {
        self.gateway.get_tx_by_wtxid(wtxid)
    }

    fn resident_ancestor_package(
        &self,
        wtxid: bitcoin_rs_primitives::Wtxid,
    ) -> Option<Vec<bitcoin_rs_primitives::Wtxid>> {
        self.gateway.ancestor_package_wtxids(wtxid)
    }

    fn resident_package(
        &self,
        wtxids: &[bitcoin_rs_primitives::Wtxid],
    ) -> Option<Vec<Arc<bitcoin_rs_primitives::Tx>>> {
        self.gateway.resident_package(wtxids)
    }
}

#[test]
fn announced_inventory_is_known_before_dispatch_gateway_callbacks() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin::secp256k1::rand::SeedableRng as _;
    use bitcoin_rs_mempool::{
        AdmissionOrigin, Mempool, MempoolEntry, MempoolGateway, MempoolLimits,
    };

    for announces_pending in [false, true] {
        let table = Arc::new(crate::PeerTable::new());
        let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_447));
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(outbound_tx);
        table.register(addr, lease.clone());
        table.publish_info(addr, &lease, peer_info(addr, 0));
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(
                MempoolLimits::default(),
            ))),
            None,
            bitcoin_rs_consensus::ValidationEngine::Native,
            None,
        ));
        let tx = Arc::new(bitcoin_rs_primitives::Tx::default());
        let sequence = gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::clone(&tx), 100, 1_000, 1, 0, 0),
            )
            .expect("relay fixture admitted")
            .sequence_of(0)
            .expect("admission epoch");
        let now = std::time::Instant::now();
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::seed_from_u64(1484);
        assert_eq!(
            table
                .queue_transaction_relay(
                    crate::RelayRequest::new(tx.txid(), tx.wtxid(), None, sequence),
                    now,
                    &mut rng,
                )
                .attempted,
            1
        );
        let inventory = Arc::new(RelayDuringInventoryLookup {
            table: Arc::clone(&table),
            gateway,
            lease: lease.clone(),
            due: now + Duration::from_secs(31),
            calls: AtomicUsize::new(0),
        });
        let mut shared = test_shared(
            table,
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
        );
        shared.tx_inventory = Some(inventory.clone());
        let announced = if announces_pending {
            *tx.txid().as_bytes()
        } else {
            [9; 32]
        };
        let mut wire = Vec::new();
        crate::wire::write_message(
            &mut wire,
            shared.magic,
            &crate::Message::Inv(vec![Inventory::Transaction(
                bitcoin::Txid::from_byte_array(announced),
            )]),
        )
        .expect("inventory frame");
        let mut peer = Peer::new(
            ScriptedStream {
                script: io::Cursor::new(wire),
            },
            shared.magic,
        );
        peer.state = PeerState::Ready;
        assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_ok());
        assert_eq!(inventory.calls.load(Ordering::Relaxed), 1);
        let echoed = outbound_rx
            .try_iter()
            .any(|frame| matches!(frame.message(), crate::Message::Inv(_)));
        assert_eq!(
            echoed, !announces_pending,
            "only the announced identity suppresses the pending relay"
        );
    }
}

#[test]
fn message_loop_disconnects_saturated_peer() {
    let (outbound_tx, _outbound_rx) = crossbeam_channel::unbounded();
    let lease =
        crate::PeerLease::new_with_budget(outbound_tx, false, OutboundBudget::new(1, ping_len()));

    let mut wire = Vec::new();
    crate::wire::write_message(&mut wire, Magic::BITCOIN, &crate::Message::Ping(41))
        .expect("ping encodes");
    crate::wire::write_message(&mut wire, Magic::BITCOIN, &crate::Message::Ping(42))
        .expect("ping encodes");
    let mut peer = Peer::new(
        ScriptedStream {
            script: io::Cursor::new(wire),
        },
        Magic::BITCOIN,
    );
    peer.state = PeerState::Ready;

    let shared = test_shared(
        Arc::new(crate::PeerTable::new()),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    );
    let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_447));

    let result = run_message_loop(&mut peer, addr, &lease, &shared, None);
    assert!(result.is_err(), "saturation must end the message loop");
    assert!(lease.is_cancelled());
}

fn queued(
    messages: &[crate::Message],
) -> (
    crate::PeerLease,
    crossbeam_channel::Receiver<crate::QueuedFrame>,
) {
    let (tx, rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx);
    for message in messages {
        lease
            .send(message.clone())
            .expect("a fresh queue admits the message");
    }
    (lease, rx)
}

#[test]
fn collect_write_burst_coalesces_control_until_a_bulk_payload() {
    let (lease, rx) = queued(&[
        crate::Message::Ping(0),
        crate::Message::Pong(1),
        crate::Message::Block(bitcoin_rs_primitives::BlockPayload::from_local(
            bitcoin_rs_primitives::Block::default(),
        )),
        crate::Message::Ping(2),
    ]);
    let first = rx.try_recv().expect("the first queued frame");

    let (burst, leftover) = collect_write_burst(first, &rx);

    let messages: Vec<_> = burst.iter().map(|frame| frame.message().clone()).collect();
    assert_eq!(
        messages,
        vec![crate::Message::Ping(0), crate::Message::Pong(1)]
    );
    assert!(matches!(
        leftover.as_ref().map(crate::QueuedFrame::message),
        Some(crate::Message::Block(_))
    ));
    assert_eq!(
        lease.budget_handle().pending().0,
        4,
        "every frame keeps its charge while it is in the burst or the leftover"
    );
    drop((burst, leftover));
    assert_eq!(
        lease.budget_handle().pending().0,
        1,
        "dropping the burst returns exactly its frames' charges"
    );
    assert!(matches!(
        rx.try_recv().map(crate::QueuedFrame::into_message),
        Ok(crate::Message::Ping(2))
    ));
}

#[test]
fn collect_write_burst_emits_a_bulk_payload_alone() {
    let (_lease, rx) = queued(&[
        crate::Message::Block(bitcoin_rs_primitives::BlockPayload::from_local(
            bitcoin_rs_primitives::Block::default(),
        )),
        crate::Message::Ping(1),
    ]);
    let first = rx.try_recv().expect("the bulk frame");
    let (burst, leftover) = collect_write_burst(first, &rx);
    assert_eq!(burst.len(), 1);
    assert!(leftover.is_none());
    assert!(matches!(
        rx.try_recv().map(crate::QueuedFrame::into_message),
        Ok(crate::Message::Ping(1))
    ));
}

#[test]
fn queued_frames_release_on_writer_exit() {
    use crate::connection::{OutboundBudget, SharedOutboundBudget};

    let shared = Arc::new(SharedOutboundBudget::with_limits(10_000, 500));
    let (bystander_tx, _bystander_rx) = crossbeam_channel::unbounded();
    let bystander = crate::PeerLease::new(bystander_tx).with_shared_budget(&shared);
    let bystander_credit = bystander
        .budget_handle()
        .try_charge(100)
        .expect("bystander charge");
    let (tx, rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new_with_budget(
        tx,
        false,
        OutboundBudget::with_block_reserve(100, 1_000_000, 500),
    )
    .with_shared_budget(&shared);
    let frame = ping_len();
    for nonce in 0..3 {
        lease
            .send(crate::Message::Ping(nonce))
            .expect("queue admits a ping");
    }
    let reservation = lease
        .try_reserve_production()
        .expect("the session's live reservation");
    assert_eq!(shared.pending(), 100 + 3 * frame + 500);

    let exit = super::WriterExit {
        budget: lease.budget_handle(),
        outbound_rx: &rx,
    };
    drop(exit);

    assert!(lease.budget_handle().writer_dead());
    assert_eq!(
        shared.pending(),
        100 + 500,
        "the three queued frames returned their own charge, nothing more"
    );
    assert_eq!(lease.budget_handle().pending(), (1, 500));
    assert!(rx.is_empty());
    assert!(matches!(
        lease.send(crate::Message::Ping(9)),
        Err(crate::OutboundRefusal::Closed(_))
    ));
    assert!(lease.is_cancelled());

    drop(reservation);
    assert_eq!(shared.pending(), 100);
    assert_eq!(lease.budget_handle().pending(), (0, 0));
    drop(bystander_credit);
    assert_eq!(shared.pending(), 0);
}
