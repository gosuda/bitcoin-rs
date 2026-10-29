use super::*;
use crate::{Message, PeerError, PeerLease, PeerRole};

fn shared() -> ConnectionShared {
    let (headers, _) = crossbeam_channel::unbounded();
    let (blocks, _) = crossbeam_channel::unbounded();
    test_shared(Arc::new(crate::PeerTable::new()), headers, blocks)
}

fn lease(manual: bool, noban: bool) -> PeerLease {
    let (tx, _) = crossbeam_channel::unbounded();
    let lease = if manual {
        PeerLease::new_manual(tx, PeerRole::FullRelay)
    } else {
        PeerLease::new(tx)
    };
    lease.with_no_ban(noban)
}

struct ServiceUpdateScript {
    bytes: std::io::Cursor<Vec<u8>>,
    update_at: Option<u64>,
    book: Arc<crate::addrman::AddressBook>,
    addr: PeerEndpoint,
}
impl std::io::Read for ServiceUpdateScript {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.update_at.is_some_and(|at| self.bytes.position() >= at) {
            self.update_at = None;
            self.book.learn_peer(
                crate::PeerRemote::Endpoint(self.addr),
                &[(self.addr, 1024, unix_time_secs())],
                unix_time_secs(),
            );
        }
        std::io::Read::read(&mut self.bytes, bytes)
    }
}
impl std::io::Write for ServiceUpdateScript {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn accepted_version_updates_once_without_replaying_on_later_steps()
-> Result<(), Box<dyn std::error::Error>> {
    for (repeated_version, protected) in
        [(true, false), (true, true), (false, false), (false, true)]
    {
        let directory = tempfile::tempdir()?;
        let address: PeerEndpoint = "8.8.8.8:8333".parse()?;
        let mut shared = shared();
        let book = crate::addrman::AddressBook::open(
            Some(directory.path().join("peers.dat")),
            shared.magic.to_bytes(),
            false,
            None,
        );
        book.learn_peer(
            crate::PeerRemote::Endpoint(address),
            &[(address, 9, unix_time_secs())],
            unix_time_secs(),
        );
        shared.address_book = Some(Arc::clone(&book));
        let lease = lease(false, protected);
        shared.peer_table.register(address, lease.clone());
        let mut wire = Vec::new();
        if protected {
            crate::wire::write_message(&mut wire, shared.magic, &Message::Verack)?;
        }
        crate::wire::write_message(
            &mut wire,
            shared.magic,
            &Message::Version(crate::handshake::version_message(
                42,
                0,
                PeerRole::FullRelay,
                ServiceFlags::from(9),
            )),
        )?;
        let update_at = (!repeated_version).then_some(u64::try_from(wire.len())?);
        if repeated_version {
            crate::wire::write_message(
                &mut wire,
                shared.magic,
                &Message::Version(crate::handshake::version_message(
                    43,
                    0,
                    PeerRole::FullRelay,
                    ServiceFlags::from(1),
                )),
            )?;
        } else {
            crate::wire::write_message(&mut wire, shared.magic, &Message::WtxidRelay)?;
            crate::wire::write_message(&mut wire, shared.magic, &Message::Verack)?;
        }
        let mut peer = Peer::new(
            ServiceUpdateScript {
                bytes: std::io::Cursor::new(wire),
                update_at,
                book: Arc::clone(&book),
                addr: address,
            },
            shared.magic,
        );
        let result = run_outbound_handshake(
            &mut peer,
            44,
            0,
            &lease,
            Instant::now() + Duration::from_secs(1),
            address,
            &shared,
        );
        if repeated_version {
            if protected {
                assert!(matches!(result, Err(PeerError::Io(_))));
            } else {
                assert!(matches!(
                    result,
                    Err(PeerError::Misbehavior("duplicate version message"))
                ));
            }
        } else {
            result?;
            assert_eq!(peer.state, crate::PeerState::Ready);
        }
        book.save();
        let bytes = std::fs::read(directory.path().join("peers-f9beb4d9.dat"))?;
        let stored: sonic_rs::Value = sonic_rs::from_slice(&bytes[..bytes.len() - 32])?;
        assert_eq!(
            stored["records"][0]["services"],
            if repeated_version { 9 } else { 1033 },
            "accepted VERSION replaces flags; later feature/VERACK must preserve a fresh gossip update"
        );
        assert_eq!(stored["records"][0]["last_success"], 0);
        assert_eq!(stored["records"][0]["tried"], false);
    }
    Ok(())
}

#[test]
fn only_current_remote_protocol_faults_change_automatic_avoidance()
-> Result<(), Box<dyn std::error::Error>> {
    let shared = shared();
    let address: PeerEndpoint = "8.8.8.8:8333".parse()?;
    let stale = lease(false, false);
    shared.peer_table.register(address, stale.clone());
    let current = lease(false, false);
    shared.peer_table.register(address, current.clone());
    let fault = PeerError::Incoming(Box::new(PeerError::BadChecksum));
    shared.note_misbehavior(address, &stale, &fault);
    assert!(!shared.banned.is_discouraged(address.address()));
    for error in [
        PeerError::Protocol("outbound queue closed"),
        PeerError::Protocol("network inactive"),
        PeerError::Protocol("p2p startup cancelled"),
        PeerError::Protocol("outbound peer lacks desirable services"),
        PeerError::PayloadTooLarge(usize::MAX),
        PeerError::Io(io::Error::from(io::ErrorKind::TimedOut)),
        PeerError::inbound(PeerError::WrongNetwork {
            expected: Magic::BITCOIN,
            actual: Magic::from_bytes([0x2f, 0x1a, 0x7c, 0x05]),
        }),
    ] {
        shared.note_misbehavior(address, &current, &error);
    }
    assert!(
        !shared.banned.is_discouraged(address.address()),
        "local/backpressure/policy failures are not remote misbehavior"
    );
    shared.note_misbehavior(address, &current, &fault);
    assert!(shared.banned.is_discouraged(address.address()));
    assert!(
        shared.banned.read().is_empty(),
        "automatic avoidance must not become a manual ban"
    );
    assert!(matches!(
        shared.check_destination(address, false),
        Err(PeerError::DiscouragedDestination(_))
    ));
    assert!(
        shared.check_destination(address, true).is_ok(),
        "manual dials bypass automatic avoidance"
    );
    assert!(
        !shared
            .banned
            .automatic_snapshot(SystemTime::now())
            .allows(address.address())
    );
    Ok(())
}

#[test]
fn invalid_wire_session_closes_and_refuses_the_next_automatic_admission()
-> Result<(), Box<dyn std::error::Error>> {
    for inbound in [false, true] {
        let shared = shared();
        let address: PeerEndpoint = "8.8.8.8:8333".parse()?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut sender = TcpStream::connect(listener.local_addr()?)?;
        let (stream, _) = listener.accept()?;
        configure_peer_stream(&stream)?;
        let counters = Arc::new(crate::PeerCounters::default());
        let local = stream.local_addr()?;
        let mut peer = Peer::new(
            crate::CountingStream::new(stream, Arc::clone(&counters)),
            Magic::BITCOIN,
        );
        peer.state = crate::PeerState::Ready;
        let (tx, rx) = crossbeam_channel::unbounded();
        let lease = if inbound {
            PeerLease::new_inbound(tx)
        } else {
            PeerLease::new(tx)
        };
        let probe = lease.clone();
        shared.peer_table.register(address, lease.clone());
        let version = crate::handshake::version_message(
            42,
            0,
            PeerRole::FullRelay,
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        );
        let mut info =
            crate::PeerInfo::outbound_from_version(address, local, &version, 0, 0, counters);
        info.inbound = inbound;
        let mut malformed = Vec::new();
        crate::wire::write_message(&mut malformed, Magic::BITCOIN, &Message::Ping(7))?;
        malformed[20] ^= 1;
        io::Write::write_all(&mut sender, &malformed)?;
        io::Write::write_all(&mut sender, &malformed)?;
        let Err(error) = run_connected_session(&mut peer, address, &shared, lease, rx, info) else {
            return Err("malformed frames must close the session with an error".into());
        };
        assert!(matches!(error, PeerError::Incoming(_)));
        assert!(probe.is_cancelled());
        assert!(shared.peer_table.sessions().is_empty());
        assert!(matches!(
            shared.check_destination(address, false),
            Err(PeerError::DiscouragedDestination(_))
        ));
        assert!(shared.banned.read().is_empty());
    }
    Ok(())
}

#[test]
fn manual_protected_and_local_connections_never_discourage_an_ip()
-> Result<(), Box<dyn std::error::Error>> {
    for (ip, manual, noban) in [
        ("8.8.8.8", true, false),
        ("8.8.4.4", false, true),
        ("127.0.0.1", false, false),
        ("::ffff:127.0.0.1", false, false),
        ("::1", false, false),
    ] {
        let shared = shared();
        let address = PeerEndpoint::new(ip.parse::<std::net::IpAddr>()?, 8333);
        let lease = lease(manual, noban);
        shared.peer_table.register(address, lease.clone());
        let error = PeerError::Misbehavior("getheaders locator too large");
        shared.note_misbehavior(address, &lease, &error);
        assert!(!shared.banned.is_discouraged(address.address()), "{ip}");
        assert_eq!(lease.ignores_protocol_error(&error), manual || noban);
        assert!(
            !lease.ignores_protocol_error(&PeerError::inbound(PeerError::WrongNetwork {
                expected: Magic::BITCOIN,
                actual: Magic::REGTEST
            })),
            "unread framing cannot be safely resumed"
        );
    }
    Ok(())
}

#[test]
fn protected_handshake_discards_bad_order_without_extending_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    for manual in [false, true] {
        let lease = lease(manual, !manual);
        let mut bytes = Vec::new();
        crate::wire::write_message(&mut bytes, Magic::REGTEST, &Message::Verack)?;
        crate::wire::write_message(
            &mut bytes,
            Magic::REGTEST,
            &Message::Version(crate::handshake::version_message(
                42,
                0,
                PeerRole::FullRelay,
                ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            )),
        )?;
        crate::wire::write_message(&mut bytes, Magic::REGTEST, &Message::Verack)?;
        let mut peer = Peer::new(std::io::Cursor::new(bytes), Magic::REGTEST);
        let (accepted, _) = crate::handshake::next_handshake_step(
            &mut peer,
            &lease,
            Instant::now() + Duration::from_secs(1),
        )?;
        assert!(matches!(accepted, Message::Version(_)));
        let (accepted, _) = crate::handshake::next_handshake_step(
            &mut peer,
            &lease,
            Instant::now() + Duration::from_secs(1),
        )?;
        assert!(matches!(accepted, Message::Verack));
        assert_eq!(peer.state, crate::peer::PeerState::Ready);
    }
    Ok(())
}
