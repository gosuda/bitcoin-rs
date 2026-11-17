use bitcoin_rs_consensus::primitives::{PeerAddress, PeerEndpoint, PeerNetwork};
use parking_lot::RwLock;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

mod identity;
mod sam;
#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    mod recovery {
        use super::*;
        use base64::Engine as _;
        use std::io::{BufRead as _, BufReader};

        /// Idle read window; an idle backend is not a backend that went away.
        const FIXTURE_IDLE: Duration = Duration::from_secs(5);

        /// How long a fixture waits for the backend to speak.
        const FIXTURE_DEADLINE: Duration = Duration::from_secs(60);

        /// How long a newly accepted connection has to open with a greeting. A
        /// connection that stays silent is a stranger, not the backend.
        const FIXTURE_GREETING: Duration = Duration::from_secs(15);

        /// Accepts the next control connection that opens with `greeting`.
        ///
        /// A listener on an ephemeral port can accept a stray connection aimed at a
        /// recycled port, so a connection that opens with anything else is dropped and
        /// the next one is accepted.
        fn accept(listener: &TcpListener, greeting: &str) -> BufReader<TcpStream> {
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let deadline = Instant::now() + FIXTURE_DEADLINE;
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking stream");
                        stream
                            .set_read_timeout(Some(FIXTURE_IDLE))
                            .expect("read deadline");
                        let mut reader = BufReader::new(stream);
                        if greeting_of(&mut reader).as_deref() == Some(greeting) {
                            return reader;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
                assert!(Instant::now() < deadline, "backend greeting deadline");
            }
        }

        /// Reads the opening line of a connection, or nothing when the connection is
        /// silent past the greeting window.
        fn greeting_of(stream: &mut BufReader<TcpStream>) -> Option<String> {
            let deadline = Instant::now() + FIXTURE_GREETING;
            let mut buf = String::new();
            loop {
                match stream.read_line(&mut buf) {
                    Ok(_) => return Some(buf),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        if Instant::now() >= deadline {
                            return None;
                        }
                    }
                    Err(_) => return None,
                }
            }
        }

        /// Reads one backend line, waiting through idle reads until EOF arrives.
        fn line(stream: &mut BufReader<TcpStream>) -> String {
            let deadline = Instant::now() + FIXTURE_DEADLINE;
            let mut buf = String::new();
            loop {
                match stream.read_line(&mut buf) {
                    Ok(_) => return buf,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        assert!(Instant::now() < deadline, "backend command deadline");
                    }
                    Err(error) => panic!("backend command: {error}"),
                }
            }
        }

        fn reply(stream: &mut BufReader<TcpStream>, response: &str) {
            stream
                .get_mut()
                .write_all(response.as_bytes())
                .expect("reply");
        }

        fn with_owner<T>(config: OverlayConfig, fixture: impl FnOnce(&Arc<OverlayTransport>) -> T) {
            struct StopOnDrop(bitcoin_rs_consensus::latch::LatchWriter);
            impl Drop for StopOnDrop {
                fn drop(&mut self) {
                    self.0.trigger();
                }
            }
            let owner = Arc::new(OverlayTransport::new(Arc::new(config)));
            let shared = shared(&owner);
            let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
            let reader = shutdown.reader();
            std::thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    if let Some(address) = owner.config.tor_control {
                        owner.run_tor(address, None, &shared, &reader);
                    } else {
                        owner.run_sam(owner.config.i2p_sam.expect("SAM"), None, &shared, &reader);
                    }
                });
                let stop = StopOnDrop(shutdown);
                let connections = fixture(&owner);
                stop.0.trigger();
                until(|| worker.is_finished());
                worker.join().expect("overlay owner");
                assert!(owner.local_onion.read().is_none());
                assert!(owner.sam.read().is_none());
                drop(connections);
            });
        }

        #[test]
        fn tor_publication_failure_reuses_key_and_shutdown_cancels_blocked_heartbeat() {
            let directory = tempfile::tempdir().expect("directory");
            let path = directory.path().join("onion.key");
            std::fs::create_dir(&path).expect("publication obstruction");
            let listener = TcpListener::bind("127.0.0.1:0").expect("control");
            let address = listener.local_addr().expect("address");
            let key = format!(
                "ED25519-V3:{}",
                base64::engine::general_purpose::STANDARD.encode([7; 64])
            );
            let service = PeerAddress::Onion([7; 32]).to_string();
            let service_id = service.strip_suffix(".onion").expect("onion address");
            with_owner(
                OverlayConfig {
                    tor_control: Some(address),
                    onion_proxy: Some(address),
                    identity_dir: directory.path().to_owned(),
                    ..OverlayConfig::default()
                },
                |owner| {
                    let mut control = accept(&listener, "AUTHENTICATE\r\n");
                    reply(&mut control, "250 OK\r\n");
                    assert!(line(&mut control).starts_with("ADD_ONION NEW:ED25519-V3 "));
                    reply(
                        &mut control,
                        &format!(
                            "250-ServiceID={service_id}\r\n250-PrivateKey={key}\r\n250 OK\r\n"
                        ),
                    );
                    assert_eq!(
                        line(&mut control),
                        "",
                        "failed publication closes the service"
                    );
                    assert!(owner.local_onion.read().is_none());
                    std::fs::rename(&path, directory.path().join("obstruction"))
                        .expect("unblock publication");

                    let mut control = accept(&listener, "AUTHENTICATE\r\n");
                    reply(&mut control, "250 OK\r\n");
                    assert!(line(&mut control).starts_with(&format!("ADD_ONION {key} ")));
                    reply(
                        &mut control,
                        &format!("250-ServiceID={service_id}\r\n250 OK\r\n"),
                    );
                    assert_eq!(line(&mut control), "GETINFO version\r\n");
                    assert_eq!(
                        identity::read(&path, identity::Kind::Tor).expect("durable key"),
                        Some(key.clone())
                    );
                    assert!(owner.local_onion.read().is_some());
                    control
                },
            );
        }

        #[test]
        fn sam_publication_failure_reuses_key_and_shutdown_cancels_blocked_accept() {
            let directory = tempfile::tempdir().expect("directory");
            let path = directory.path().join("i2p.key");
            std::fs::create_dir(&path).expect("publication obstruction");
            let listener = TcpListener::bind("127.0.0.1:0").expect("SAM");
            let public = identity::i2p_base64().encode([0; 387]);
            let private = identity::i2p_base64().encode([0; 387 + 256 + 20]);
            with_owner(
                OverlayConfig {
                    i2p_sam: Some(listener.local_addr().expect("address")),
                    i2p_accept: true,
                    identity_dir: directory.path().to_owned(),
                    ..OverlayConfig::default()
                },
                |owner| {
                    let mut control = accept(&listener, "HELLO VERSION MIN=3.1 MAX=3.3\n");
                    reply(&mut control, "HELLO REPLY RESULT=OK VERSION=3.3\n");
                    assert_eq!(line(&mut control), "DEST GENERATE SIGNATURE_TYPE=7\n");
                    reply(
                        &mut control,
                        &format!("DEST REPLY PUB={public} PRIV={private}\n"),
                    );
                    assert_eq!(
                        line(&mut control),
                        "",
                        "no session before durable publication"
                    );
                    assert!(owner.sam.read().is_none());
                    std::fs::rename(&path, directory.path().join("obstruction"))
                        .expect("unblock publication");

                    let mut control = accept(&listener, "HELLO VERSION MIN=3.1 MAX=3.3\n");
                    reply(&mut control, "HELLO REPLY RESULT=OK VERSION=3.3\n");
                    let create = line(&mut control);
                    assert!(create.starts_with("SESSION CREATE STYLE=STREAM "));
                    assert!(create.contains(&format!(" DESTINATION={private} ")));
                    reply(&mut control, "SESSION STATUS RESULT=OK\n");
                    assert_eq!(line(&mut control), "NAMING LOOKUP NAME=ME\n");
                    reply(
                        &mut control,
                        &format!("NAMING REPLY RESULT=OK NAME=ME VALUE={public}\n"),
                    );
                    assert_eq!(line(&mut control), "PING bitcoin-rs\n");
                    reply(&mut control, "PONG bitcoin-rs\n");
                    assert_eq!(
                        identity::read(&path, identity::Kind::I2p).expect("durable key"),
                        Some(private.clone())
                    );
                    let mut inbound = accept(&listener, "HELLO VERSION MIN=3.1 MAX=3.3\n");
                    reply(&mut inbound, "HELLO REPLY RESULT=OK VERSION=3.3\n");
                    assert!(line(&mut inbound).starts_with("STREAM ACCEPT ID="));
                    assert!(owner.sam.read().is_some());
                    (control, inbound)
                },
            );
        }
    }

    fn shared(owner: &Arc<OverlayTransport>) -> crate::listener::ConnectionShared {
        let mut shared = crate::listener::ConnectionShared::new(
            Arc::new(crate::PeerTable::new()),
            crate::BannedReader::fixture_empty(),
            Arc::new(crate::NetworkActivity::from_shared(Arc::new(
                AtomicBool::new(true),
            ))),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
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

    fn read_sam_line(
        reader: &mut impl std::io::BufRead,
        line: &mut String,
        stop: &AtomicBool,
    ) -> bool {
        loop {
            line.clear();
            match reader.read_line(line) {
                Ok(0) => return false,
                Ok(_) => return true,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if stop.load(Ordering::Acquire) {
                        return false;
                    }
                }
                Err(error) => panic!("SAM fixture read: {error}"),
            }
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
            for byte in [5, 0, 0, 1, 127, 0, 0, 1, 0, 0] {
                stream.write_all(&[byte]).expect("reply");
            }
            stream.write_all(b"bitcoin").expect("P2P bytes");
        });
        let mut stream = socks_unauthenticated(proxy, endpoint, &|| false).expect("SOCKS stream");
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
                socks_isolated(
                    address,
                    PeerEndpoint::new(PeerAddress::Onion([1; 32]), 8333),
                    &|| false,
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
            let error =
                socks_unauthenticated(address, PeerEndpoint::from(([8, 8, 8, 8], 8333)), &|| false)
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
    #[test]
    fn application_identity_create_cleans_temporary_file() {
        use base64::Engine as _;
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("onion.key");
        let key = format!(
            "ED25519-V3:{}",
            base64::engine::general_purpose::STANDARD.encode([7; 64])
        );
        identity::create(&path, &key, identity::Kind::Tor).expect("create identity");
        let entries = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "onion.key");
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SamRecoveryMode {
        InvalidId,
        ControlLoss,
    }

    #[test]
    fn sam_control_loss_revokes_stream_epoch_and_reconnects_without_direct_fallback() {
        sam_session_recovery(SamRecoveryMode::ControlLoss);
    }

    #[test]
    fn sam_invalid_id_revokes_stream_epoch_and_reconnects_while_control_responds() {
        sam_session_recovery(SamRecoveryMode::InvalidId);
    }

    fn handle_sam_recovery_connection(
        mut stream: TcpStream,
        stop: &Arc<AtomicBool>,
        controls: &std::sync::atomic::AtomicUsize,
        break_control: &Arc<AtomicBool>,
        public: &str,
        mode: SamRecoveryMode,
    ) {
        use std::io::BufReader;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut line = String::new();
        if !read_sam_line(&mut reader, &mut line, stop) || line != "HELLO VERSION MIN=3.1 MAX=3.3\n"
        {
            return;
        }
        stream
            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.3\n")
            .expect("hello reply");
        let mut epoch = 0;
        while !stop.load(Ordering::Acquire) {
            if !read_sam_line(&mut reader, &mut line, stop) {
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
                        format!("NAMING REPLY RESULT=OK NAME=ME VALUE={public}\n").as_bytes(),
                    )
                    .expect("local destination");
            } else if line.starts_with("STREAM CONNECT ") {
                if mode == SamRecoveryMode::InvalidId
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
                if mode == SamRecoveryMode::ControlLoss
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
    }

    fn spawn_sam_recovery_fixture(
        listener: TcpListener,
        stop: Arc<AtomicBool>,
        controls: Arc<std::sync::atomic::AtomicUsize>,
        break_control: Arc<AtomicBool>,
        public: String,
        mode: SamRecoveryMode,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut connections = Vec::new();
            while !stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("blocking fixture stream");
                        let stop = Arc::clone(&stop);
                        let controls = Arc::clone(&controls);
                        let break_control = Arc::clone(&break_control);
                        let public = public.clone();
                        connections.push(std::thread::spawn(move || {
                            handle_sam_recovery_connection(
                                stream,
                                &stop,
                                &controls,
                                &break_control,
                                &public,
                                mode,
                            );
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
    }

    fn sam_session_recovery(mode: SamRecoveryMode) {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
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
        let shutdown_latch = bitcoin_rs_consensus::latch::LatchWriter::new();
        let controls = Arc::new(AtomicUsize::new(0));
        let break_control = Arc::new(AtomicBool::new(false));
        let public = identity::i2p_base64().encode([0; 387]);
        let endpoint = PeerEndpoint::new(PeerAddress::I2p(Sha256::digest([0; 387]).into()), 18444);
        let fixture = spawn_sam_recovery_fixture(
            listener,
            Arc::clone(&shutdown),
            Arc::clone(&controls),
            Arc::clone(&break_control),
            public,
            mode,
        );
        let workers = owner
            .start(&shared, &shutdown_latch.reader())
            .expect("backend worker");
        until(|| owner.sam.read().is_some());
        let mut connected = owner.connect(endpoint, &|| false).expect("SAM stream");
        let mut bytes = [0; 7];
        connected.stream.read_exact(&mut bytes).expect("P2P bytes");
        assert_eq!(&bytes, b"bitcoin");
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx).with_transport_alive(connected.alive.clone());
        shared.peer_table.register(endpoint, lease.clone());
        assert!(!lease.is_cancelled());
        let (other_tx, _other_rx) = crossbeam_channel::unbounded();
        let independent = crate::PeerLease::new(other_tx)
            .with_transport_alive(Some(Arc::new(AtomicBool::new(true))));
        let other_endpoint = PeerEndpoint::new(PeerAddress::I2p([8; 32]), 18444);
        shared
            .peer_table
            .register(other_endpoint, independent.clone());
        break_control.store(true, Ordering::Release);
        if mode == SamRecoveryMode::InvalidId {
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
        assert!(
            shared
                .peer_table
                .is_current(replacement.source(Some(endpoint)))
        );
        assert!(
            !shared.banned.is_discouraged(endpoint.address()),
            "local router loss is not remote misbehavior"
        );
        stop_sam_workers(
            workers,
            &shutdown,
            &shutdown_latch,
            &replacement,
            &independent,
            fixture,
        );
    }

    fn stop_sam_workers(
        workers: Vec<std::thread::JoinHandle<Result<(), crate::listener::ListenerError>>>,
        shutdown: &AtomicBool,
        latch: &bitcoin_rs_consensus::latch::LatchWriter,
        replacement: &crate::PeerLease,
        independent: &crate::PeerLease,
        fixture: std::thread::JoinHandle<()>,
    ) {
        shutdown.store(true, Ordering::Release);
        latch.trigger();
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
}
mod tor;

#[derive(Clone, Debug)]
pub struct OverlayConfig {
    pub proxy: Option<SocketAddr>,
    pub onion_proxy: Option<SocketAddr>,
    pub randomize_credentials: bool,
    pub onlynet: Vec<PeerNetwork>,
    pub i2p_sam: Option<SocketAddr>,
    pub i2p_accept: bool,
    pub tor_control: Option<SocketAddr>,
    pub tor_cookie: Option<PathBuf>,
    pub identity_dir: PathBuf,
    pub port: u16,
}
impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            proxy: None,
            onion_proxy: None,
            randomize_credentials: true,
            onlynet: Vec::new(),
            i2p_sam: None,
            i2p_accept: false,
            tor_control: None,
            tor_cookie: None,
            identity_dir: PathBuf::new(),
            port: 8333,
        }
    }
}
impl OverlayConfig {
    pub fn validate(&self) -> io::Result<()> {
        for socket in [self.proxy, self.onion_proxy, self.i2p_sam, self.tor_control]
            .into_iter()
            .flatten()
        {
            if socket.port() == 0 || !socket.ip().is_loopback() {
                return Err(invalid(
                    "overlay services must use nonzero loopback socket endpoints",
                ));
            }
        }
        if self.i2p_accept && self.i2p_sam.is_none() {
            return Err(invalid("i2p-accept requires i2p-sam"));
        }
        if self.tor_cookie.is_some() && self.tor_control.is_none() {
            return Err(invalid("tor-cookie requires tor-control"));
        }
        if self.tor_control.is_some() && self.onion_proxy.is_none() {
            return Err(invalid("tor-control requires onion-proxy"));
        }
        if (self.i2p_accept || self.tor_control.is_some())
            && (self.identity_dir.as_os_str().is_empty() || self.port == 0)
        {
            return Err(invalid(
                "inbound overlay services require an identity directory and port",
            ));
        }
        for network in &self.onlynet {
            if !self.configured(*network) {
                return Err(invalid("onlynet selects an unconfigured overlay route"));
            }
        }
        if self.i2p_accept && !self.allows(PeerNetwork::I2p)
            || self.tor_control.is_some() && !self.allows(PeerNetwork::Onion)
        {
            return Err(invalid("inbound overlay service is excluded by onlynet"));
        }
        Ok(())
    }
    #[must_use]
    pub fn tor_configured(&self) -> bool {
        self.onion_proxy.is_some() || self.proxy.is_some() || self.tor_control.is_some()
    }

    #[must_use]
    pub fn i2p_configured(&self) -> bool {
        self.i2p_sam.is_some()
    }

    pub fn configured(&self, network: PeerNetwork) -> bool {
        match network {
            PeerNetwork::Ipv4 | PeerNetwork::Ipv6 => true,
            PeerNetwork::Onion => self.onion_proxy.is_some(),
            PeerNetwork::I2p => self.i2p_sam.is_some(),
        }
    }
    pub fn allows(&self, network: PeerNetwork) -> bool {
        self.configured(network) && (self.onlynet.is_empty() || self.onlynet.contains(&network))
    }
    pub(crate) fn local_dns_allowed(&self) -> bool {
        self.proxy.is_none() && (self.allows(PeerNetwork::Ipv4) || self.allows(PeerNetwork::Ipv6))
    }

    #[must_use]
    pub fn dial_routes(&self) -> crate::DialRoutes {
        fn label(network: PeerNetwork) -> bitcoin_rs_consensus::primitives::NetworkLabel {
            use bitcoin_rs_consensus::primitives::NetworkLabel as Label;
            match network {
                PeerNetwork::Ipv4 => Label::Ipv4,
                PeerNetwork::Ipv6 => Label::Ipv6,
                PeerNetwork::Onion => Label::Onion,
                PeerNetwork::I2p => Label::I2p,
            }
        }
        crate::DialRoutes {
            proxy: self.proxy,
            onion: self.onion_proxy,
            proxy_randomize_credentials: self.randomize_credentials,
            sam_session: None,
            onlynet: self.onlynet.iter().map(|network| label(*network)).collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OverlayNetworkState {
    pub network: PeerNetwork,
    pub allowed: bool,
    pub operational: bool,
    pub proxy: Option<SocketAddr>,
    pub local_address: Option<PeerEndpoint>,
}

pub(crate) struct Connected {
    pub(crate) stream: TcpStream,
    pub(crate) alive: Option<Arc<AtomicBool>>,
}

pub(crate) struct OverlayTransport {
    pub(crate) config: Arc<OverlayConfig>,
    sam: RwLock<Option<sam::Session>>,
    local_onion: RwLock<Option<PeerEndpoint>>,
}
impl OverlayTransport {
    pub(crate) fn new(config: Arc<OverlayConfig>) -> Self {
        Self {
            config,
            sam: RwLock::new(None),
            local_onion: RwLock::new(None),
        }
    }

    pub(crate) fn states(&self, table: &crate::PeerTable) -> Vec<OverlayNetworkState> {
        [
            PeerNetwork::Ipv4,
            PeerNetwork::Ipv6,
            PeerNetwork::Onion,
            PeerNetwork::I2p,
        ]
        .into_iter()
        .map(|network| {
            let local_address = match network {
                PeerNetwork::Onion => *self.local_onion.read(),
                PeerNetwork::I2p => self
                    .sam
                    .read()
                    .as_ref()
                    .filter(|session| {
                        self.config.i2p_accept && session.alive.load(Ordering::Acquire)
                    })
                    .map(|session| session.local_address),
                _ => None,
            };
            OverlayNetworkState {
                network,
                allowed: self.config.allows(network),
                operational: local_address.is_some()
                    || table
                        .infos()
                        .iter()
                        .any(|peer| peer.addr.network() == network),
                proxy: match network {
                    PeerNetwork::Onion => self.config.onion_proxy,
                    PeerNetwork::I2p => self.config.i2p_sam,
                    _ => self.config.proxy,
                },
                local_address,
            }
        })
        .collect()
    }

    pub(crate) fn connect(
        &self,
        endpoint: PeerEndpoint,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Connected> {
        if !self.config.allows(endpoint.address().network()) {
            return Err(invalid("destination network disabled"));
        }
        let stream = match endpoint.address() {
            PeerAddress::Ip(_) => {
                if let Some(proxy) = self.config.proxy {
                    if self.config.randomize_credentials {
                        socks_isolated(proxy, endpoint, cancelled)
                    } else {
                        socks_unauthenticated(proxy, endpoint, cancelled)
                    }
                } else {
                    TcpStream::connect_timeout(
                        &endpoint
                            .socket_addr()
                            .ok_or_else(|| invalid("missing IP socket"))?,
                        SETUP_TIMEOUT,
                    )
                }
            }
            PeerAddress::Onion(_) => {
                let onion_proxy = self
                    .config
                    .onion_proxy
                    .ok_or_else(|| invalid("onion route disabled"))?;
                if self.config.randomize_credentials {
                    socks_isolated(onion_proxy, endpoint, cancelled)
                } else {
                    socks_unauthenticated(onion_proxy, endpoint, cancelled)
                }
            }
            PeerAddress::I2p(_) => return self.sam_connect(endpoint, cancelled),
        }?;
        Ok(Connected {
            stream,
            alive: None,
        })
    }

    pub(crate) fn resolve(
        &self,
        text: &str,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Vec<PeerEndpoint>> {
        use std::net::ToSocketAddrs as _;
        if let Ok(endpoint) = text.parse::<PeerEndpoint>() {
            return if self.config.allows(endpoint.address().network()) {
                Ok(vec![endpoint])
            } else {
                Err(invalid("destination network disabled"))
            };
        }
        let (host, port) = text
            .rsplit_once(':')
            .ok_or_else(|| invalid("peer requires host:port"))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| invalid("invalid peer port"))?;
        let host = host.to_ascii_lowercase();
        let normalized = host.trim_end_matches('.');
        if normalized.ends_with(".onion") {
            return Err(invalid("invalid Tor destination"));
        }
        if normalized.ends_with(".i2p") {
            if !self.config.allows(PeerNetwork::I2p)
                || host != normalized
                || !host
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'.')
            {
                return Err(invalid("I2P naming disabled or invalid name"));
            }
            return Ok(vec![self.sam_lookup(&host, port, cancelled)?]);
        }
        if !self.config.local_dns_allowed() {
            return Err(invalid(
                "local DNS disabled by routing policy; use an IP or overlay destination",
            ));
        }
        if cancelled() {
            return Err(cancelled_error());
        }
        Ok((host.as_str(), port)
            .to_socket_addrs()?
            .map(PeerEndpoint::from)
            .filter(|endpoint| self.config.allows(endpoint.address().network()))
            .collect())
    }

    pub(crate) fn start(
        self: &Arc<Self>,
        shared: &crate::listener::ConnectionShared,
        shutdown: &bitcoin_rs_consensus::latch::LatchReader,
    ) -> io::Result<Vec<std::thread::JoinHandle<Result<(), crate::listener::ListenerError>>>> {
        self.config.validate()?;
        let i2p_key = if self.config.i2p_accept {
            identity::read(
                &self.config.identity_dir.join("i2p.key"),
                identity::Kind::I2p,
            )?
        } else {
            None
        };
        let tor_key = if self.config.tor_control.is_some() {
            identity::read(
                &self.config.identity_dir.join("onion.key"),
                identity::Kind::Tor,
            )?
        } else {
            None
        };
        let abort_latch = shutdown.child();
        let abort_reader = abort_latch.reader();
        let mut workers = Vec::new();
        if let Some(address) = self.config.i2p_sam
            && self.config.allows(PeerNetwork::I2p)
        {
            let owner = Arc::clone(self);
            let shared = shared.clone();
            let sam_shutdown = abort_reader.clone();
            workers.push(
                std::thread::Builder::new()
                    .name("bitcoin-rs-ivnp-sam".into())
                    .spawn(move || {
                        owner.run_sam(address, i2p_key, &shared, &sam_shutdown);
                        Ok(())
                    })?,
            );
        }
        if let Some(address) = self.config.tor_control {
            let owner = Arc::clone(self);
            let shared = shared.clone();
            let tor_shutdown = abort_reader;
            match std::thread::Builder::new()
                .name("bitcoin-rs-tor-control".into())
                .spawn(move || {
                    owner.run_tor(address, tor_key, &shared, &tor_shutdown);
                    Ok(())
                }) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    abort_latch.trigger();
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error);
                }
            }
        }
        Ok(workers)
    }
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RemoteConnectFailure(String);

fn remote_failure(message: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        RemoteConnectFailure(message.into()),
    )
}

pub(crate) fn remote_connect_failed(error: &io::Error) -> bool {
    matches!(error.get_ref(), Some(inner) if inner.is::<RemoteConnectFailure>())
}
fn cancelled_error() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "overlay operation cancelled")
}
const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);
struct Setup<'a> {
    stream: TcpStream,
    deadline: Instant,
    cancelled: &'a dyn Fn() -> bool,
}
impl<'a> Setup<'a> {
    fn new(address: SocketAddr, cancelled: &'a dyn Fn() -> bool) -> io::Result<Self> {
        Self::new_until(address, cancelled, Instant::now() + SETUP_TIMEOUT)
    }
    fn new_until(
        address: SocketAddr,
        cancelled: &'a dyn Fn() -> bool,
        deadline: Instant,
    ) -> io::Result<Self> {
        let stream = connect(address, cancelled, deadline)?;
        stream.set_read_timeout(Some(POLL))?;
        stream.set_write_timeout(Some(POLL))?;
        Ok(Self {
            stream,
            deadline,
            cancelled,
        })
    }
    fn check(&self) -> io::Result<()> {
        if (self.cancelled)() {
            Err(cancelled_error())
        } else if Instant::now() >= self.deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "overlay setup deadline",
            ))
        } else {
            Ok(())
        }
    }
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.check()?;
            match self.stream.read(&mut bytes[offset..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "overlay service closed",
                    ));
                }
                Ok(count) => offset += count,
                Err(error) if poll_error(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.check()?;
            match self.stream.write(&bytes[offset..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "overlay service closed",
                    ));
                }
                Ok(count) => offset += count,
                Err(error) if poll_error(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn line(&mut self) -> io::Result<String> {
        let mut line = Vec::new();
        let mut byte = [0];
        while line.len() < 16_384 {
            self.read(&mut byte)?;
            if byte[0] == b'\n' {
                return String::from_utf8(line)
                    .map(|line| line.trim_end_matches('\r').to_owned())
                    .map_err(|_| invalid("non-UTF8 overlay reply"));
            }
            line.push(byte[0]);
        }
        Err(invalid("oversized overlay reply"))
    }
    fn finish(self) -> io::Result<TcpStream> {
        self.stream.set_read_timeout(None)?;
        self.stream.set_write_timeout(None)?;
        Ok(self.stream)
    }
}
fn poll_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}
fn connect(
    address: SocketAddr,
    cancelled: &dyn Fn() -> bool,
    deadline: Instant,
) -> io::Result<TcpStream> {
    loop {
        if cancelled() {
            return Err(cancelled_error());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "transport connect deadline",
            ));
        }
        match TcpStream::connect_timeout(&address, POLL.min(remaining)) {
            Ok(stream) => return Ok(stream),
            Err(error) if poll_error(&error) => {}
            Err(error) => return Err(error),
        }
    }
}

fn socks_unauthenticated(
    proxy: SocketAddr,
    endpoint: PeerEndpoint,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<TcpStream> {
    socks_impl(proxy, endpoint, false, cancelled)
}

fn socks_isolated(
    proxy: SocketAddr,
    endpoint: PeerEndpoint,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<TcpStream> {
    socks_impl(proxy, endpoint, true, cancelled)
}

fn socks_impl(
    proxy: SocketAddr,
    endpoint: PeerEndpoint,
    isolate: bool,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<TcpStream> {
    use bitcoin::secp256k1::rand::RngCore as _;
    let mut setup = Setup::new(proxy, cancelled)?;
    setup.write(&[5, 1, if isolate { 2 } else { 0 }])?;
    let mut response = [0; 2];
    setup.read(&mut response)?;
    if response != [5, if isolate { 2 } else { 0 }] {
        return Err(invalid("SOCKS authentication method refused"));
    }
    if isolate {
        let mut credentials = [0_u8; 32];
        bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut credentials);
        let mut authentication = vec![1, 16];
        authentication.extend_from_slice(&credentials[..16]);
        authentication.push(16);
        authentication.extend_from_slice(&credentials[16..]);
        setup.write(&authentication)?;
        setup.read(&mut response)?;
        if response != [1, 0] {
            return Err(invalid("SOCKS authentication refused"));
        }
    }
    let mut request = vec![5, 1, 0];
    match endpoint.address() {
        PeerAddress::Ip(std::net::IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        PeerAddress::Ip(std::net::IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        PeerAddress::Onion(_) => {
            let host = endpoint.address().to_string();
            request.extend_from_slice(&[
                3,
                u8::try_from(host.len()).map_err(|_| invalid("SOCKS hostname too long"))?,
            ]);
            request.extend_from_slice(host.as_bytes());
        }
        _ => return Err(invalid("unsupported SOCKS destination")),
    }
    if matches!(endpoint.address(), PeerAddress::Onion(_)) {
        setup.deadline = Instant::now() + Duration::from_secs(60);
    }
    request.extend_from_slice(&endpoint.port().to_be_bytes());
    setup.write(&request)?;
    let mut reply = [0; 4];
    setup.read(&mut reply)?;
    if reply[..3] != [5, 0, 0] {
        if reply[0] == 5
            && reply[2] == 0
            && matches!(reply[3], 1 | 3 | 4)
            && matches!(reply[1], 3..=6)
        {
            return Err(remote_failure("SOCKS destination unreachable or refused"));
        }
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "SOCKS connect refused",
        ));
    }
    let length = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut count = [0];
            setup.read(&mut count)?;
            usize::from(count[0])
        }
        _ => return Err(invalid("malformed SOCKS bound address")),
    };
    setup.read(&mut vec![0; length + 2])?;
    setup.finish()
}
