use super::*;
use base64::Engine as _;
use std::io::{BufRead as _, BufReader};

fn accept(listener: &TcpListener) -> BufReader<TcpStream> {
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).expect("blocking stream");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read deadline");
                return BufReader::new(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "backend retry deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

fn line(stream: &mut BufReader<TcpStream>) -> String {
    let mut line = String::new();
    stream.read_line(&mut line).expect("backend command or EOF");
    line
}

fn reply(stream: &mut BufReader<TcpStream>, response: &str) {
    stream
        .get_mut()
        .write_all(response.as_bytes())
        .expect("reply");
}

fn with_owner<T>(config: OverlayConfig, fixture: impl FnOnce(&Arc<OverlayTransport>) -> T) {
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let owner = Arc::new(OverlayTransport::new(Arc::new(config)));
    let shared = shared(&owner);
    let shutdown = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            if let Some(address) = owner.config.tor_control {
                owner.run_tor(address, None, &shared, &shutdown);
            } else {
                owner.run_sam(owner.config.i2p_sam.expect("SAM"), None, &shared, &shutdown);
            }
        });
        let _stop = StopOnDrop(Arc::clone(&shutdown));
        let connections = fixture(&owner);
        shutdown.store(true, Ordering::Release);
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
            let mut control = accept(&listener);
            assert_eq!(line(&mut control), "AUTHENTICATE\r\n");
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

            let mut control = accept(&listener);
            assert_eq!(line(&mut control), "AUTHENTICATE\r\n");
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
            let mut control = accept(&listener);
            assert_eq!(line(&mut control), "HELLO VERSION MIN=3.1 MAX=3.3\n");
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

            let mut control = accept(&listener);
            assert_eq!(line(&mut control), "HELLO VERSION MIN=3.1 MAX=3.3\n");
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
            let mut inbound = accept(&listener);
            assert_eq!(line(&mut inbound), "HELLO VERSION MIN=3.1 MAX=3.3\n");
            reply(&mut inbound, "HELLO REPLY RESULT=OK VERSION=3.3\n");
            assert!(line(&mut inbound).starts_with("STREAM ACCEPT ID="));
            assert!(owner.sam.read().is_some());
            (control, inbound)
        },
    );
}
