use super::*;
use std::net::TcpListener;

mod recovery;

fn shared(owner: &Arc<OverlayTransport>) -> crate::listener::ConnectionShared {
    let mut shared = crate::listener::ConnectionShared::new(
        Arc::new(crate::PeerTable::new()),
        crate::BannedReader::fixture_empty(),
        Arc::new(crate::NetworkActivity::from_shared(Arc::new(
            AtomicBool::new(true),
        ))),
        Arc::new(AtomicBool::new(false)),
        None,
        bitcoin::p2p::Magic::REGTEST,
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
        None,
        None,
        crate::ListenerExtras::default(),
    );
    shared.overlay = Arc::clone(owner);
    shared
}
fn until(predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(Instant::now() < deadline, "fixture deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn socks_routes_onion_as_a_domain_and_preserves_stream_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("proxy");
    let proxy = listener.local_addr().expect("address");
    let endpoint = PeerEndpoint::new(PeerAddress::Onion([7; 32]), 8333);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut hello = [0; 3];
        stream.read_exact(&mut hello).expect("hello");
        assert_eq!(hello, [5, 1, 0]);
        stream.write_all(&[5, 0]).expect("method");
        let mut request = [0; 5];
        stream.read_exact(&mut request).expect("request");
        assert_eq!(request[..4], [5, 1, 0, 3]);
        let mut domain = vec![0; usize::from(request[4])];
        stream.read_exact(&mut domain).expect("domain");
        assert_eq!(domain, endpoint.address().to_string().as_bytes());
        let mut port = [0; 2];
        stream.read_exact(&mut port).expect("port");
        assert_eq!(u16::from_be_bytes(port), 8333);
        // Fragmenting the reply must not lose framing; bound IP is transport metadata only.
        for byte in [5, 0, 0, 1, 127, 0, 0, 1, 0, 0] {
            stream.write_all(&[byte]).expect("reply");
        }
        stream.write_all(b"bitcoin").expect("P2P bytes");
    });
    let mut stream = socks(proxy, endpoint, false, &|| false).expect("SOCKS stream");
    let mut bytes = [0; 7];
    stream.read_exact(&mut bytes).expect("unconsumed P2P bytes");
    assert_eq!(&bytes, b"bitcoin");
    server.join().expect("fixture");
}

#[test]
fn socks_requires_the_selected_auth_policy_and_refuses_bad_replies() {
    for response in [[5, 0], [4, 2], [5, 255]] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy");
        let address = listener.local_addr().expect("address");
        let fixture = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).expect("hello");
            assert_eq!(hello, [5, 1, 2]);
            stream.write_all(&response).expect("reply");
        });
        assert!(
            socks(
                address,
                PeerEndpoint::new(PeerAddress::Onion([1; 32]), 8333),
                true,
                &|| false
            )
            .is_err()
        );
        fixture.join().expect("fixture");
    }
}

#[test]
fn socks_destination_refusals_are_distinct_from_local_and_malformed_failures() {
    for reply in [
        [5, 1, 0, 1],
        [5, 2, 0, 1],
        [5, 3, 0, 1],
        [5, 4, 0, 1],
        [5, 5, 0, 1],
        [5, 6, 0, 1],
        [5, 7, 0, 1],
        [5, 8, 0, 1],
        [4, 5, 0, 1],
        [5, 5, 1, 1],
        [5, 5, 0, 9],
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy");
        let address = listener.local_addr().expect("address");
        let fixture = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream.read_exact(&mut [0; 3]).expect("hello");
            stream.write_all(&[5, 0]).expect("method");
            stream.read_exact(&mut [0; 10]).expect("IP request");
            stream.write_all(&reply).expect("refusal");
        });
        let error = socks(
            address,
            PeerEndpoint::from(([8, 8, 8, 8], 8333)),
            false,
            &|| false,
        )
        .expect_err("refused connection");
        assert_eq!(
            remote_connect_failed(&error),
            matches!(reply, [5, 3..=6, 0, 1])
        );
        fixture.join().expect("fixture");
    }
    assert!(!remote_connect_failed(&io::Error::from(
        io::ErrorKind::ConnectionRefused
    )));
}

#[test]
fn setup_retains_partial_reads_and_obeys_deadline_and_cancellation() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("proxy");
    let address = listener.local_addr().expect("address");
    let fixture = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream.write_all(&[5]).expect("partial");
        std::thread::sleep(Duration::from_millis(250));
        stream.write_all(&[0]).expect("rest");
        std::thread::sleep(Duration::from_millis(300));
    });
    let stop = AtomicBool::new(false);
    let cancelled = || stop.load(Ordering::Acquire);
    let mut setup = Setup::new(address, &cancelled).expect("connect");
    let mut reply = [0; 2];
    setup.read(&mut reply).expect("partial read survives polls");
    assert_eq!(reply, [5, 0]);
    setup.deadline = Instant::now();
    assert_eq!(
        setup.read(&mut [0]).expect_err("deadline").kind(),
        io::ErrorKind::TimedOut
    );
    setup.deadline = Instant::now() + SETUP_TIMEOUT;
    stop.store(true, Ordering::Release);
    assert_eq!(
        setup.read(&mut [0]).expect_err("cancel").kind(),
        io::ErrorKind::Interrupted
    );
    fixture.join().expect("fixture");
}

#[test]
fn overlay_only_resolution_and_admission_never_fall_back_to_ip_or_dns() {
    let config = OverlayConfig {
        onlynet: vec![PeerNetwork::Onion],
        onion_proxy: Some("127.0.0.1:9050".parse().expect("proxy")),
        ..OverlayConfig::default()
    };
    config.validate().expect("config");
    let transport = OverlayTransport::new(config.into());
    for text in [
        "127.0.0.1:8333",
        "localhost:8333",
        "bad.onion:8333",
        "bad.onion.:8333",
        "name.i2p:8333",
        "name.i2p.:8333",
    ] {
        assert!(transport.resolve(text, &|| false).is_err(), "{text}");
    }
    assert!(
        transport
            .resolve(
                &PeerEndpoint::new(PeerAddress::Onion([2; 32]), 8333).to_string(),
                &|| false
            )
            .is_ok()
    );
    assert!(
        transport
            .connect("127.0.0.1:1".parse().expect("IP"), &|| false)
            .is_err()
    );
}

#[test]
fn application_identity_is_create_once_and_corruption_is_explicit() {
    use base64::Engine as _;
    let dir = tempfile::tempdir().expect("directory");
    let path = dir.path().join("onion.key");
    assert!(
        identity::read(&path, identity::Kind::Tor)
            .expect("absent")
            .is_none()
    );
    let key = format!(
        "ED25519-V3:{}",
        base64::engine::general_purpose::STANDARD.encode([9; 64])
    );
    identity::create(&path, &key, identity::Kind::Tor).expect("create");
    assert_eq!(
        identity::read(&path, identity::Kind::Tor).expect("reuse"),
        Some(key.clone())
    );
    identity::create(&path, &key, identity::Kind::Tor).expect("retry same identity durability");
    let other = format!(
        "ED25519-V3:{}",
        base64::engine::general_purpose::STANDARD.encode([8; 64])
    );
    assert!(identity::create(&path, &other, identity::Kind::Tor).is_err());
    std::fs::write(&path, "damaged").expect("damage");
    assert!(identity::read(&path, identity::Kind::Tor).is_err());
    assert_eq!(std::fs::read_to_string(path).expect("preserved"), "damaged");
}

#[cfg(unix)]
#[test]
fn identity_reader_refuses_existing_and_dangling_symlinks() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().expect("directory");
    let target = directory.path().join("target");
    let link = directory.path().join("identity");
    std::fs::write(&target, b"operator bytes").expect("target");
    symlink(&target, &link).expect("symlink");
    assert!(identity::read(&link, identity::Kind::Tor).is_err());
    assert_eq!(std::fs::read(&target).expect("target"), b"operator bytes");
    std::fs::remove_file(&target).expect("remove target");
    assert!(identity::read(&link, identity::Kind::Tor).is_err());
    assert!(link.is_symlink());
}

#[test]
fn sam_private_destination_requires_the_encryption_and_signing_fields() {
    use base64::Engine as _;
    let mut bytes = vec![0; 387 + 256 + 20];
    let encoded = identity::i2p_base64().encode(&bytes);
    identity::validate(&encoded, identity::Kind::I2p).expect("complete legacy private key");
    bytes.pop();
    assert!(
        identity::validate(&identity::i2p_base64().encode(bytes), identity::Kind::I2p).is_err()
    );
}

#[test]
fn sam_public_destination_validates_certificate_structure() {
    use base64::Engine as _;
    let encode = |bytes: &[u8]| identity::i2p_base64().encode(bytes);
    let mut public = vec![0; 387];
    assert!(identity::public_destination(&encode(&public)).is_ok());
    public[384] = 255;
    assert!(identity::public_destination(&encode(&public)).is_err());
    public[384] = 5;
    assert!(identity::public_destination(&encode(&public)).is_err());
    public[386] = 4;
    public.extend_from_slice(&[0, 7, 0, 0]);
    assert!(identity::public_destination(&encode(&public)).is_ok());
    public[390] = 255;
    assert!(identity::public_destination(&encode(&public)).is_err());
    public[390] = 0;
    public.push(0);
    assert!(identity::public_destination(&encode(&public)).is_err());
}

#[test]
fn sam_control_loss_revokes_stream_epoch_and_reconnects_without_direct_fallback() {
    sam_session_recovery(false);
}

#[test]
fn sam_invalid_id_revokes_stream_epoch_and_reconnects_while_control_responds() {
    sam_session_recovery(true);
}

#[expect(
    clippy::too_many_lines,
    reason = "One fixture follows control setup, loss, epoch revocation, reconnect, and shutdown"
)]
fn sam_session_recovery(invalid_id: bool) {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    use std::io::{BufRead as _, BufReader};
    use std::sync::atomic::AtomicUsize;
    let listener = TcpListener::bind("127.0.0.1:0").expect("SAM fixture");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    let owner = Arc::new(OverlayTransport::new(Arc::new(OverlayConfig {
        i2p_sam: Some(address),
        onlynet: vec![PeerNetwork::I2p],
        ..OverlayConfig::default()
    })));
    let shared = shared(&owner);
    let shutdown = Arc::new(AtomicBool::new(false));
    let controls = Arc::new(AtomicUsize::new(0));
    let break_control = Arc::new(AtomicBool::new(false));
    let public = identity::i2p_base64().encode([0; 387]);
    let endpoint = PeerEndpoint::new(PeerAddress::I2p(Sha256::digest([0; 387]).into()), 18444);
    let fixture = {
        let stop = Arc::clone(&shutdown);
        let controls = Arc::clone(&controls);
        let break_control = Arc::clone(&break_control);
        std::thread::spawn(move || {
            let mut connections = Vec::new();
            while !stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("blocking fixture stream");
                        let stop = Arc::clone(&stop);
                        let controls = Arc::clone(&controls);
                        let break_control = Arc::clone(&break_control);
                        let public = public.clone();
                        connections.push(std::thread::spawn(move || {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(3)))
                                .expect("timeout");
                            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                            let mut line = String::new();
                            reader.read_line(&mut line).expect("hello");

                            assert_eq!(line, "HELLO VERSION MIN=3.1 MAX=3.3\n");
                            stream
                                .write_all(b"HELLO REPLY RESULT=OK VERSION=3.3\n")
                                .expect("hello reply");
                            let mut epoch = 0;
                            while !stop.load(Ordering::Acquire) {
                                line.clear();
                                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                    break;
                                }

                                if line.starts_with("SESSION CREATE STYLE=STREAM ") {
                                    assert!(line.contains("DESTINATION=TRANSIENT"));
                                    epoch = controls.fetch_add(1, Ordering::AcqRel) + 1;
                                    stream
                                        .write_all(b"SESSION STATUS RESULT=OK\n")
                                        .expect("session");
                                } else if line.starts_with("NAMING LOOKUP NAME=") {
                                    stream
                                        .write_all(
                                            format!(
                                                "NAMING REPLY RESULT=OK NAME=ME VALUE={public}\n"
                                            )
                                            .as_bytes(),
                                        )
                                        .expect("local destination");
                                } else if line.starts_with("STREAM CONNECT ") {
                                    if invalid_id
                                        && break_control.load(Ordering::Acquire)
                                        && controls.load(Ordering::Acquire) == 1
                                    {
                                        stream
                                            .write_all(b"STREAM STATUS RESULT=INVALID_ID\n")
                                            .expect("invalid session");
                                        break;
                                    }
                                    assert!(line.contains(&format!("DESTINATION={public}")));
                                    assert!(line.contains("TO_PORT=18444 SILENT=false"));
                                    stream
                                        .write_all(b"STREAM STATUS RESULT=OK\nbitcoin")
                                        .expect("stream");
                                    while !stop.load(Ordering::Acquire) {
                                        std::thread::sleep(POLL);
                                    }
                                    break;
                                } else if line == "PING bitcoin-rs\n" {
                                    if !invalid_id
                                        && epoch == 1
                                        && break_control.load(Ordering::Acquire)
                                    {
                                        break;
                                    }
                                    stream.write_all(b"PONG bitcoin-rs\n").expect("heartbeat");
                                } else {
                                    panic!("unexpected SAM command");
                                }
                            }
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            }
            for connection in connections {
                connection.join().expect("connection fixture");
            }
        })
    };
    let workers = owner.start(&shared, &shutdown).expect("backend worker");
    until(|| owner.sam.read().is_some());
    let mut connected = owner.connect(endpoint, &|| false).expect("SAM stream");
    let mut bytes = [0; 7];
    connected.stream.read_exact(&mut bytes).expect("P2P bytes");
    assert_eq!(&bytes, b"bitcoin");
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = crate::PeerLease::new(tx).with_transport_alive(connected.alive.clone());
    shared.peer_table.register(endpoint, lease.clone());
    assert!(!lease.is_cancelled());
    // A shared network label is not epoch ownership. This lease carries a
    // different marker and must survive both old-session recovery and shutdown.
    let (other_tx, _other_rx) = crossbeam_channel::unbounded();
    let independent =
        crate::PeerLease::new(other_tx).with_transport_alive(Some(Arc::new(AtomicBool::new(true))));
    let other_endpoint = PeerEndpoint::new(PeerAddress::I2p([8; 32]), 18444);
    shared
        .peer_table
        .register(other_endpoint, independent.clone());
    break_control.store(true, Ordering::Release);
    if invalid_id {
        assert!(owner.connect(endpoint, &|| false).is_err());
    }
    until(|| lease.is_cancelled());
    until(|| controls.load(Ordering::Acquire) >= 2 && owner.sam.read().is_some());
    assert!(
        connected
            .alive
            .as_ref()
            .is_some_and(|alive| !alive.load(Ordering::Acquire)),
        "old stream never adopts new session"
    );
    assert!(
        !independent.is_cancelled(),
        "retirement is scoped to one epoch"
    );
    let mut fresh = owner
        .connect(endpoint, &|| false)
        .expect("replacement stream");
    fresh
        .stream
        .read_exact(&mut bytes)
        .expect("replacement P2P bytes");
    assert_eq!(&bytes, b"bitcoin");
    let (tx, _rx) = crossbeam_channel::unbounded();
    let replacement = crate::PeerLease::new(tx).with_transport_alive(fresh.alive.clone());
    shared.peer_table.register(endpoint, replacement.clone());
    assert!(!shared.peer_table.remove_current(endpoint, &lease));
    connected
        .alive
        .as_ref()
        .expect("old epoch")
        .store(false, Ordering::Release);
    assert!(
        !replacement.is_cancelled(),
        "late old-epoch revocation cannot reach replacement"
    );
    assert!(shared.peer_table.is_current(replacement.source(endpoint)));
    assert!(
        !shared.banned.is_discouraged(endpoint.address()),
        "local router loss is not remote misbehavior"
    );
    shutdown.store(true, Ordering::Release);
    for worker in workers {
        worker.join().expect("worker").expect("backend");
    }
    assert!(
        replacement.is_cancelled(),
        "the new epoch retires at its own shutdown"
    );
    assert!(!independent.is_cancelled());
    fixture.join().expect("SAM fixture");
}
