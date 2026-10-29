//! External Tor control service, with a dedicated unprivileged forwarding listener.
use super::{
    AtomicBool, Duration, Instant, Ordering, OverlayTransport, POLL, PeerEndpoint, SETUP_TIMEOUT,
    Setup, SocketAddr, identity, invalid, io, pause,
};
use bitcoin::hashes::{Hash as _, HashEngine as _, hmac, sha256};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::secp256k1::rand::RngCore as _;
use std::io::Read as _;
use std::net::TcpListener;
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
    pub(super) fn run_tor(
        &self,
        address: SocketAddr,
        mut key: Option<String>,
        shared: &crate::listener::ConnectionShared,
        shutdown: &AtomicBool,
    ) {
        let cancelled = || shutdown.load(Ordering::Acquire) || shared.is_session_cancelled();
        let mut backoff = Duration::from_secs(1);
        while !cancelled() {
            let result = (|| -> io::Result<()> {
                let listener = TcpListener::bind("127.0.0.1:0")?;
                listener.set_nonblocking(true)?;
                let forwarding = listener.local_addr()?;
                let mut control = Setup::new(address, &cancelled)?;
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
                    key = Some(private.to_owned());
                }
                if let Some(private) = &key {
                    identity::create(
                        &self.config.identity_dir.join("onion.key"),
                        private,
                        identity::Kind::Tor,
                    )?;
                }
                *self.local_onion.write() = Some(endpoint);
                tracing::info!(service = %endpoint, %forwarding, "Tor inbound service active");
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
                            crate::listener::admit_anonymous_tor(stream, shared);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            pause(&cancelled, POLL);
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
            if let Err(error) = result {
                if !cancelled() {
                    tracing::warn!(%error, "Tor inbound service unavailable; retrying");
                }
            }
            pause(&cancelled, backoff);
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Write as _};

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
}
