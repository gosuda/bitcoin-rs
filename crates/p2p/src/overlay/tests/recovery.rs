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
    struct StopOnDrop(bitcoin_rs_chain::LatchWriter);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.trigger();
        }
    }
    let owner = Arc::new(OverlayTransport::new(Arc::new(config)));
    let shared = shared(&owner);
    let shutdown = bitcoin_rs_chain::LatchWriter::new();
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
                &format!("250-ServiceID={service_id}\r\n250-PrivateKey={key}\r\n250 OK\r\n"),
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
