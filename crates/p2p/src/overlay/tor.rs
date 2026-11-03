use super::{
    Duration, Instant, OverlayTransport, POLL, PeerEndpoint, SETUP_TIMEOUT, Setup, SocketAddr,
    identity, invalid, io,
};
use bitcoin::hashes::{Hash as _, HashEngine as _, hmac, sha256};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::secp256k1::rand::RngCore as _;
use std::io::Read as _;
use std::net::{TcpListener, TcpStream};
fn reply(setup: &mut Setup<'_>) -> io::Result<Vec<String>> {
    let mut lines = Vec::new();
    for _ in 0..32 {
        let line = setup.line()?;
        if !line.starts_with("250") || line.len() < 4 {
            return Err(invalid("Tor control request refused or malformed reply"));
        }
        let terminal = line.as_bytes()[3] == b' ';
        if !terminal && line.as_bytes()[3] != b'-' {
            return Err(invalid("unsupported Tor control reply"));
        }
        lines.push(line[4..].to_owned());
        if terminal {
            return Ok(lines);
        }
    }
    Err(invalid("oversized Tor control reply"))
}

fn safecookie_hash(key: &[u8], cookie: &[u8], client: &[u8], server: &[u8]) -> [u8; 32] {
    let mut engine = hmac::HmacEngine::<sha256::Hash>::new(key);
    engine.input(cookie);
    engine.input(client);
    engine.input(server);
    hmac::Hmac::<sha256::Hash>::from_engine(engine).to_byte_array()
}

fn authenticate(setup: &mut Setup<'_>, cookie_path: Option<&std::path::Path>) -> io::Result<()> {
    let Some(path) = cookie_path else {
        setup.write(b"AUTHENTICATE\r\n")?;
        reply(setup)?;
        return Ok(());
    };
    let mut cookie = Vec::with_capacity(33);
    std::fs::File::open(path)?
        .take(33)
        .read_to_end(&mut cookie)?;
    if cookie.len() != 32 {
        return Err(invalid("Tor cookie must contain 32 bytes"));
    }
    setup.write(b"PROTOCOLINFO 1\r\n")?;
    let info = reply(setup)?;
    let mut methods = info
        .iter()
        .filter_map(|line| line.strip_prefix("AUTH "))
        .flat_map(|line| line.split_ascii_whitespace())
        .filter_map(|field| field.strip_prefix("METHODS="));
    let offered = methods
        .next()
        .ok_or_else(|| invalid("Tor control authentication methods missing"))?;
    if methods.next().is_some() {
        return Err(invalid("duplicate Tor control authentication methods"));
    }
    if !offered.split(',').any(|method| method == "SAFECOOKIE") {
        return Err(invalid("Tor control does not offer SAFECOOKIE"));
    }
    let mut nonce = [0u8; 32];
    bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut nonce);
    setup.write(
        format!(
            "AUTHCHALLENGE SAFECOOKIE {}\r\n",
            nonce.to_lower_hex_string()
        )
        .as_bytes(),
    )?;
    let lines = reply(setup)?;
    let line = lines
        .iter()
        .find_map(|line| line.strip_prefix("AUTHCHALLENGE "))
        .ok_or_else(|| invalid("Tor control challenge missing"))?;
    let parse_field = |name: &str| -> io::Result<[u8; 32]> {
        let mut values = line
            .split_ascii_whitespace()
            .filter_map(|token| token.split_once('='))
            .filter(|(key, _)| *key == name)
            .map(|(_, value)| value);
        let value = values
            .next()
            .ok_or_else(|| invalid("Tor control challenge field missing"))?;
        if values.next().is_some() {
            return Err(invalid("duplicate Tor control challenge field"));
        }
        <[u8; 32]>::from_hex(value).map_err(|_| invalid("invalid Tor control challenge field"))
    };
    let server_hash = parse_field("SERVERHASH")?;
    let server_nonce = parse_field("SERVERNONCE")?;
    let expected = safecookie_hash(
        b"Tor safe cookie authentication server-to-controller hash",
        &cookie,
        &nonce,
        &server_nonce,
    );
    if server_hash != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Tor SAFECOOKIE server hash mismatch",
        ));
    }
    let client_hash = safecookie_hash(
        b"Tor safe cookie authentication controller-to-server hash",
        &cookie,
        &nonce,
        &server_nonce,
    );
    setup.write(format!("AUTHENTICATE {}\r\n", client_hash.to_lower_hex_string()).as_bytes())?;
    reply(setup)?;
    Ok(())
}

impl OverlayTransport {
    fn provision_onion<'a>(
        &self,
        address: SocketAddr,
        key: &mut Option<String>,
        forwarding: SocketAddr,
        cancelled: &'a dyn Fn() -> bool,
    ) -> io::Result<(PeerEndpoint, Setup<'a>)> {
        let mut control = Setup::new(address, cancelled)?;
        authenticate(&mut control, self.config.tor_cookie.as_deref())?;
        control.write(
            format!(
                "ADD_ONION {} Port={},{}\r\n",
                key.as_deref().unwrap_or("NEW:ED25519-V3"),
                self.config.port,
                forwarding
            )
            .as_bytes(),
        )?;
        let lines = reply(&mut control)?;
        let service = lines
            .iter()
            .find_map(|line| line.strip_prefix("ServiceID="))
            .ok_or_else(|| invalid("Tor control missing service ID"))?;
        let endpoint = format!("{service}.onion:{}", self.config.port)
            .parse::<PeerEndpoint>()
            .map_err(invalid)?;
        if key.is_none() {
            let private = lines
                .iter()
                .find_map(|line| line.strip_prefix("PrivateKey="))
                .ok_or_else(|| invalid("Tor control missing private key"))?;
            *key = Some(private.to_owned());
        }
        if let Some(private) = key.as_deref() {
            identity::create(
                &self.config.identity_dir.join("onion.key"),
                private,
                identity::Kind::Tor,
            )?;
        }
        Ok((endpoint, control))
    }

    pub(super) fn run_tor(
        &self,
        address: SocketAddr,
        mut key: Option<String>,
        shared: &crate::listener::ConnectionShared,
        shutdown: &bitcoin_rs_chain::LatchReader,
    ) {
        let cancelled = || shutdown.is_triggered() || shared.is_session_cancelled();
        let mut backoff = Duration::from_secs(1);
        while !cancelled() {
            let result = (|| -> io::Result<()> {
                let listener = TcpListener::bind("127.0.0.1:0")?;
                listener.set_nonblocking(true)?;
                let forwarding = listener.local_addr()?;
                let (endpoint, mut control) =
                    self.provision_onion(address, &mut key, forwarding, &cancelled)?;
                *self.local_onion.write() = Some(endpoint);
                tracing::info!(service = %endpoint, %forwarding, "Tor inbound service active");
                let control_wake = control.stream.try_clone()?;
                let _hook_shutdown = shutdown.on_cancel(move || {
                    let _ = control_wake.shutdown(std::net::Shutdown::Both);
                });
                let listen_wake = listener.try_clone()?;
                let _hook_listen = shutdown.on_cancel(move || {
                    if let Ok(addr) = listen_wake.local_addr() {
                        let _ = TcpStream::connect(addr);
                    }
                });
                let healthy_since = Instant::now();
                let mut next_heartbeat = Instant::now();
                while !cancelled() {
                    if Instant::now() >= next_heartbeat {
                        control.deadline = Instant::now() + SETUP_TIMEOUT;
                        control.write(b"GETINFO version\r\n")?;
                        reply(&mut control)?;
                        if healthy_since.elapsed() >= Duration::from_secs(60) {
                            backoff = Duration::from_secs(1);
                        }
                        next_heartbeat = Instant::now() + Duration::from_secs(1);
                    }
                    match listener.accept() {
                        Ok((stream, _forward_socket)) => {
                            if cancelled() {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                break;
                            }
                            crate::listener::admit_anonymous_tor(stream, shared);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            crossbeam_channel::select! {
                                recv(shutdown.closed()) -> _ => break,
                                recv(shared.session_cancel.closed()) -> _ => break,
                                recv(crossbeam_channel::after(POLL)) -> _ => {}
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            })();
            *self.local_onion.write() = None;
            for session in shared.peer_table.sessions() {
                if matches!(session.addr, crate::PeerRemote::AnonymousTor(_)) {
                    session.lease.cancel();
                }
            }
            if let Err(error) = &result {
                if !cancelled() {
                    tracing::warn!(%error, "Tor inbound service unavailable; retrying");
                }
            }
            crossbeam_channel::select! {
                recv(shutdown.closed()) -> _ => {},
                recv(shared.session_cancel.closed()) -> _ => {},
                recv(crossbeam_channel::after(backoff)) -> _ => {},
            }
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::sync::atomic::AtomicBool;

    fn test_shared(owner: &std::sync::Arc<OverlayTransport>) -> crate::listener::ConnectionShared {
        let mut shared = crate::listener::ConnectionShared::new(
            std::sync::Arc::new(crate::PeerTable::new()),
            crate::BannedReader::fixture_empty(),
            std::sync::Arc::new(crate::NetworkActivity::from_shared(std::sync::Arc::new(
                AtomicBool::new(true),
            ))),
            bitcoin_rs_chain::LatchReader::fixture_never(),
            None,
            bitcoin::p2p::Magic::REGTEST,
            crossbeam_channel::unbounded().0,
            crossbeam_channel::unbounded().0,
            None,
            None,
            crate::ListenerExtras::default(),
        );
        shared.overlay = std::sync::Arc::clone(owner);
        shared
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Tor SAFECOOKIE control endpoint"]
    fn external_tor_safecookie_authentication() {
        let address = std::env::var("BITCOIN_RS_TEST_TOR_CONTROL")
            .expect("control endpoint")
            .parse()
            .expect("control socket");
        let cookie = std::env::var_os("BITCOIN_RS_TEST_TOR_COOKIE").expect("cookie path");
        let mut setup = Setup::new(address, &|| false).expect("connect");
        authenticate(&mut setup, Some(std::path::Path::new(&cookie))).expect("authenticate");
        setup.write(b"GETINFO version\r\n").expect("GETINFO");
        assert!(
            reply(&mut setup)
                .expect("version")
                .iter()
                .any(|line| line.starts_with("version="))
        );
    }

    #[test]
    fn safecookie_hash_matches_independent_vectors() {
        let cookie = [7; 32];
        let client = [8; 32];
        let server = [9; 32];
        assert_eq!(
            safecookie_hash(
                b"Tor safe cookie authentication server-to-controller hash",
                &cookie,
                &client,
                &server
            )
            .to_lower_hex_string(),
            "ccc316d685a291115dfae269666c7b18bdb14aa6bffa43453a35a84f5b556475"
        );
        assert_eq!(
            safecookie_hash(
                b"Tor safe cookie authentication controller-to-server hash",
                &cookie,
                &client,
                &server
            )
            .to_lower_hex_string(),
            "d960215167ca3d7d91b2f68132429c4039829f4125d8372bf57268137ce66cbe"
        );
    }

    #[test]
    fn safecookie_authenticates_only_after_valid_server_challenge() {
        for mismatch in [false, true] {
            let directory = tempfile::tempdir().expect("directory");
            let path = directory.path().join("cookie");
            std::fs::write(&path, [7; 32]).expect("cookie");
            let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
            let address = listener.local_addr().expect("address");
            let fixture = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("timeout");
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut line = String::new();
                reader.read_line(&mut line).expect("protocolinfo");
                assert_eq!(line, "PROTOCOLINFO 1\r\n");
                stream
                    .write_all(
                        b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE\r\n250 OK\r\n",
                    )
                    .expect("info");
                line.clear();
                reader.read_line(&mut line).expect("challenge");
                let client = <[u8; 32]>::from_hex(
                    line.trim()
                        .strip_prefix("AUTHCHALLENGE SAFECOOKIE ")
                        .expect("challenge command"),
                )
                .expect("client nonce");
                let server = [9; 32];
                let mut hash = safecookie_hash(
                    b"Tor safe cookie authentication server-to-controller hash",
                    &[7; 32],
                    &client,
                    &server,
                );
                if mismatch {
                    hash[0] ^= 1;
                }
                stream
                    .write_all(
                        format!(
                            "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                            hash.to_lower_hex_string(),
                            server.to_lower_hex_string()
                        )
                        .as_bytes(),
                    )
                    .expect("challenge response");
                line.clear();
                let count = reader
                    .read_line(&mut line)
                    .expect("authentication or close");
                if mismatch {
                    assert_eq!(count, 0);
                } else {
                    let expected = safecookie_hash(
                        b"Tor safe cookie authentication controller-to-server hash",
                        &[7; 32],
                        &client,
                        &server,
                    );
                    assert_eq!(
                        line,
                        format!("AUTHENTICATE {}\r\n", expected.to_lower_hex_string())
                    );
                    stream.write_all(b"250 OK\r\n").expect("authenticated");
                }
            });
            let mut setup = Setup::new(address, &|| false).expect("setup");
            assert_eq!(authenticate(&mut setup, Some(&path)).is_ok(), !mismatch);
            drop(setup);
            fixture.join().expect("fixture");
        }
    }

    #[test]
    fn tor_accept_loop_exits_on_latch_trigger_while_pending_accept() {
        let control_listener = TcpListener::bind("127.0.0.1:0").expect("bind control");
        let control_addr = control_listener.local_addr().expect("control addr");
        let (probe_tx, probe_rx) = crossbeam_channel::bounded(1);
        let fake_control = std::thread::spawn(move || {
            let (mut stream, _) = control_listener.accept().expect("accept control");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            reader.read_line(&mut line).expect("read AUTH");
            stream.write_all(b"250 OK\r\n").expect("write AUTH OK");
            line.clear();
            reader.read_line(&mut line).expect("read ADD_ONION");
            let service_id = bitcoin_rs_primitives::PeerEndpoint::tor_onion_hostname(&[7; 32]);
            let private_key = format!(
                "ED25519-V3:{}",
                base64::engine::general_purpose::STANDARD.encode([7u8; 64])
            );
            stream
                .write_all(
                    format!(
                        "250-ServiceID={service_id}\r\n250-PrivateKey={private_key}\r\n250 OK\r\n"
                    )
                    .as_bytes(),
                )
                .expect("write ADD_ONION reply");
            line.clear();
            while let Ok(count) = reader.read_line(&mut line) {
                if count == 0 {
                    break;
                }
                if line == "GETINFO version\r\n" {
                    let _ = probe_tx.send(());
                    std::thread::sleep(Duration::from_millis(500));
                    let _ = stream.write_all(b"250-version=0.4.8.10\r\n250 OK\r\n");
                }
                line.clear();
            }
        });

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let transport = std::sync::Arc::new(OverlayTransport::new(std::sync::Arc::new(
            crate::overlay::OverlayConfig {
                tor_control: Some(control_addr),
                identity_dir: temp_dir.path().to_path_buf(),
                port: 8333,
                ..crate::overlay::OverlayConfig::default()
            },
        )));
        let shared = test_shared(&transport);
        let latch = bitcoin_rs_chain::LatchWriter::new();
        let shutdown = latch.reader();
        let worker_transport = std::sync::Arc::clone(&transport);
        let (joined_tx, joined_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            worker_transport.run_tor(control_addr, None, &shared, &shutdown);
            let _ = joined_tx.send(());
        });

        let active = Instant::now() + Duration::from_secs(3);
        while transport.local_onion.read().is_none() && Instant::now() < active {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            transport.local_onion.read().is_some(),
            "tor service must become active"
        );
        probe_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("tor worker must request the control heartbeat");
        let started = Instant::now();
        latch.trigger();
        joined_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("tor accept worker must exit after the latch trigger");
        assert!(
            started.elapsed() < Duration::from_millis(60),
            "accept loop must wake from the latch, not the poll tick: {:?}",
            started.elapsed()
        );
        worker.join().expect("join tor worker");
        fake_control.join().expect("join fake control");
    }
}
