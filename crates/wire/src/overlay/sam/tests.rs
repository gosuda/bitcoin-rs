use super::*;
use crate::PeerNetwork;
use base64::Engine as _;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;

#[test]
fn naming_failure_attribution_preserves_peer_retry_accounting() {
    for (reply, remote) in [
        ("NAMING REPLY RESULT=KEY_NOT_FOUND\n", true),
        ("NAMING REPLY RESULT=INVALID_KEY\n", false),
        ("NAMING REPLY RESULT=I2P_ERROR\n", false),
        ("NAMING REPLY RESULT=TIMEOUT\n", false),
        ("STREAM STATUS RESULT=KEY_NOT_FOUND\n", false),
        ("NAMING REPLY RESULT=KEY_NOT_FOUND RESULT=OK\n", false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("SAM");
        let address = listener.local_addr().expect("address");
        let endpoint = PeerEndpoint::new(PeerAddress::I2p([1; 32]), 8333);
        let fixture = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("naming connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            reader.read_line(&mut line).expect("hello");
            stream
                .write_all(b"HELLO REPLY RESULT=OK VERSION=3.3\n")
                .expect("hello reply");
            line.clear();
            reader.read_line(&mut line).expect("lookup");
            assert_eq!(line, format!("NAMING LOOKUP NAME={}\n", endpoint.address()));
            stream.write_all(reply.as_bytes()).expect("naming reply");
            line.clear();
            assert_eq!(reader.read_line(&mut line).expect("closed"), 0);
            listener.set_nonblocking(true).expect("nonblocking");
            assert_eq!(
                listener.accept().expect_err("no stream connection").kind(),
                io::ErrorKind::WouldBlock
            );
        });
        let transport = OverlayTransport::new(Arc::new(crate::overlay::OverlayConfig {
            i2p_sam: Some(address),
            ..crate::overlay::OverlayConfig::default()
        }));
        let alive = Arc::new(AtomicBool::new(true));
        *transport.sam.write() = Some(Session {
            id: "fixture".to_owned(),
            alive: Arc::clone(&alive),
            local_address: endpoint,
        });
        let error = match transport.sam_connect(endpoint, &|| false) {
            Ok(_) => panic!("failed naming opened a stream"),
            Err(error) => error,
        };
        fixture.join().expect("fixture");
        assert_eq!(
            super::super::remote_connect_failed(&error),
            remote,
            "{reply}"
        );
        assert!(alive.load(Ordering::Acquire));
    }
}

#[test]
fn naming_mismatch_or_invalid_destination_never_opens_a_stream() {
    for public in [
        identity::i2p_base64().encode([0; 387]),
        identity::i2p_base64().encode([0; 388]),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("SAM");
        let address = listener.local_addr().expect("address");
        let fixture = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("naming connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            reader.read_line(&mut line).expect("hello");
            stream
                .write_all(b"HELLO REPLY RESULT=OK VERSION=3.3\n")
                .expect("hello reply");
            line.clear();
            reader.read_line(&mut line).expect("lookup");
            assert!(line.starts_with("NAMING LOOKUP NAME="));
            stream
                .write_all(format!("NAMING REPLY RESULT=OK VALUE={public}\n").as_bytes())
                .expect("naming reply");
            line.clear();
            assert_eq!(reader.read_line(&mut line).expect("closed"), 0);
            listener.set_nonblocking(true).expect("nonblocking");
            assert_eq!(
                listener.accept().expect_err("no stream connection").kind(),
                io::ErrorKind::WouldBlock
            );
        });
        let transport = OverlayTransport::new(Arc::new(crate::overlay::OverlayConfig {
            i2p_sam: Some(address),
            ..crate::overlay::OverlayConfig::default()
        }));
        let endpoint = PeerEndpoint::new(PeerAddress::I2p([1; 32]), 8333);
        *transport.sam.write() = Some(Session {
            id: "fixture".to_owned(),
            alive: Arc::new(AtomicBool::new(true)),
            local_address: endpoint,
        });
        let error = match transport.sam_connect(endpoint, &|| false) {
            Ok(_) => panic!("untrusted destination accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!super::super::remote_connect_failed(&error));
        fixture.join().expect("fixture");
    }
}

#[test]
fn advertised_i2p_address_belongs_to_a_live_accepting_session() {
    let local = PeerEndpoint::new(PeerAddress::I2p([7; 32]), 8333);
    for accept in [false, true] {
        let transport = OverlayTransport::new(Arc::new(crate::overlay::OverlayConfig {
            i2p_accept: accept,
            i2p_sam: Some("127.0.0.1:7656".parse().expect("SAM socket")),
            ..crate::overlay::OverlayConfig::default()
        }));
        let table = crate::PeerTable::new();
        let state = || {
            transport
                .states(&table)
                .into_iter()
                .find(|state| state.network == PeerNetwork::I2p)
                .expect("I2P state")
        };
        let alive = Arc::new(AtomicBool::new(true));
        assert!(state().local_address.is_none());
        *transport.sam.write() = Some(Session {
            id: "fixture".to_owned(),
            alive: Arc::clone(&alive),
            local_address: local,
        });
        assert_eq!(state().local_address, accept.then_some(local));
        assert_eq!(state().operational, accept);
        alive.store(false, Ordering::Release);
        assert!(state().local_address.is_none());
        assert!(!state().operational);
        assert!(transport.sam_session().is_err());
        transport.sam.write().take();
        assert!(state().local_address.is_none());
    }
}

#[test]
fn late_invalid_session_retires_only_its_observed_epoch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("SAM");
    let address = listener.local_addr().expect("address");
    let public = [0u8; 387];
    let endpoint = PeerEndpoint::new(PeerAddress::I2p(Sha256::digest(public).into()), 8333);
    let (sent, received) = std::sync::mpsc::channel();
    let (release, gate) = std::sync::mpsc::channel();
    let fixture = std::thread::spawn(move || {
        for naming in [true, false] {
            let (mut stream, _) = listener.accept().expect("connection");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            reader.read_line(&mut line).expect("hello");
            stream
                .write_all(b"HELLO REPLY RESULT=OK VERSION=3.3\n")
                .expect("hello reply");
            line.clear();
            reader.read_line(&mut line).expect("request");
            if naming {
                stream
                    .write_all(
                        format!(
                            "NAMING REPLY RESULT=OK VALUE={}\n",
                            identity::i2p_base64().encode(public)
                        )
                        .as_bytes(),
                    )
                    .expect("naming reply");
            } else {
                assert!(line.starts_with("STREAM CONNECT ID=old "));
                sent.send(()).expect("request observed");
                gate.recv_timeout(Duration::from_secs(3)).expect("release");
                stream
                    .write_all(b"STREAM STATUS RESULT=INVALID_ID\n")
                    .expect("late reply");
            }
        }
    });
    let transport = Arc::new(OverlayTransport::new(Arc::new(
        crate::overlay::OverlayConfig {
            i2p_sam: Some(address),
            ..crate::overlay::OverlayConfig::default()
        },
    )));
    let old = Arc::new(AtomicBool::new(true));
    *transport.sam.write() = Some(Session {
        id: "old".into(),
        alive: Arc::clone(&old),
        local_address: endpoint,
    });
    let caller = Arc::clone(&transport);
    let dial = std::thread::spawn(move || caller.sam_connect(endpoint, &|| false).is_err());
    received
        .recv_timeout(Duration::from_secs(3))
        .expect("stream request");
    let replacement = Arc::new(AtomicBool::new(true));
    *transport.sam.write() = Some(Session {
        id: "new".into(),
        alive: Arc::clone(&replacement),
        local_address: endpoint,
    });
    release.send(()).expect("release");
    assert!(dial.join().expect("dial"));
    fixture.join().expect("fixture");
    assert!(!old.load(Ordering::Acquire));
    assert!(replacement.load(Ordering::Acquire));
    assert_eq!(transport.sam_session().expect("replacement").0, "new");
}

#[test]
fn naming_and_stream_share_the_dial_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("SAM");
    let address = listener.local_addr().expect("address");
    let public = [0u8; 387];
    let endpoint = PeerEndpoint::new(PeerAddress::I2p(Sha256::digest(public).into()), 8333);
    let fixture = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("naming");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("hello");
        stream
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.3\n")
            .expect("hello reply");
        line.clear();
        reader.read_line(&mut line).expect("lookup");
        std::thread::sleep(Duration::from_millis(200));
        stream
            .write_all(
                format!(
                    "NAMING REPLY RESULT=OK VALUE={}\n",
                    identity::i2p_base64().encode(public)
                )
                .as_bytes(),
            )
            .expect("naming reply");
        listener.set_nonblocking(true).expect("nonblocking");
        let end = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(stream) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("stream accept: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking stream");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        line.clear();
        reader.read_line(&mut line).expect("hello");
        stream
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.3\n")
            .expect("hello reply");
        line.clear();
        reader.read_line(&mut line).expect("stream request");
        assert!(line.starts_with("STREAM CONNECT "));
        line.clear();
        assert_eq!(
            reader.read_line(&mut line).expect("deadline closes stream"),
            0
        );
    });
    let transport = OverlayTransport::new(Arc::new(crate::overlay::OverlayConfig {
        i2p_sam: Some(address),
        ..crate::overlay::OverlayConfig::default()
    }));
    *transport.sam.write() = Some(Session {
        id: "fixture".to_owned(),
        alive: Arc::new(AtomicBool::new(true)),
        local_address: endpoint,
    });
    let started = Instant::now();
    let error = match transport.sam_connect_until(
        endpoint,
        &|| false,
        started + Duration::from_millis(500),
    ) {
        Ok(_) => panic!("stalled stream accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(!super::super::remote_connect_failed(&error));
    assert!(started.elapsed() < Duration::from_secs(2));
    fixture.join().expect("fixture");
}

#[test]
fn only_explicit_stream_destination_failures_are_remote_attempts() {
    for (reply, remote) in [
        ("STREAM STATUS RESULT=CANT_REACH_PEER\n", true),
        ("STREAM STATUS RESULT=TIMEOUT\n", true),
        ("STREAM STATUS RESULT=I2P_ERROR\n", false),
        ("STREAM STATUS RESULT=INVALID_ID\n", false),
        ("SESSION STATUS RESULT=TIMEOUT\n", false),
        ("STREAM STATUS RESULT=TIMEOUT RESULT=TIMEOUT\n", false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("SAM");
        let address = listener.local_addr().expect("address");
        let fixture = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream.write_all(reply.as_bytes()).expect("status");
        });
        let mut setup = Setup::new(address, &|| false).expect("setup");
        let error = status(&mut setup, "STREAM STATUS ").expect_err("refused stream");
        assert_eq!(super::super::remote_connect_failed(&error), remote);
        fixture.join().expect("fixture");
    }
}

#[test]
fn negotiation_refuses_unsupported_duplicate_and_malformed_replies() {
    for reply in [
        "HELLO REPLY RESULT=OK VERSION=4.0\n",
        "HELLO REPLY RESULT=NOVERSION\n",
        "HELLO REPLY RESULT=OK RESULT=OK VERSION=3.3\n",
        "SESSION STATUS RESULT=OK VERSION=3.3\n",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let fixture = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("clone"))
                .read_line(&mut line)
                .expect("request");
            stream.write_all(reply.as_bytes()).expect("reply");
        });
        let mut setup = Setup::new(address, &|| false).expect("setup");
        assert!(hello(&mut setup).is_err());
        fixture.join().expect("fixture");
    }
}
