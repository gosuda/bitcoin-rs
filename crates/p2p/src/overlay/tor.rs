//! External Tor control service, with a dedicated unprivileged forwarding listener.
use super::{
    AtomicBool, Duration, Instant, Ordering, OverlayTransport, POLL, PeerAddress, PeerEndpoint,
    SETUP_TIMEOUT, Setup, SocketAddr, identity, invalid, io, pause,
};
use std::io::Read as _;
use std::net::TcpListener;
use std::sync::atomic::AtomicU64;
static NEXT_ANONYMOUS: AtomicU64 = AtomicU64::new(1);
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
impl OverlayTransport {
    #[expect(
        clippy::too_many_lines,
        reason = "One service owner keeps key publication, control lifetime and inbound teardown ordered"
    )]
    pub(super) fn run_tor(
        &self,
        address: SocketAddr,
        mut key: Option<String>,
        shared: &crate::listener::ConnectionShared,
        shutdown: &AtomicBool,
    ) {
        use bitcoin::hex::DisplayHex as _;
        let cancelled = || shutdown.load(Ordering::Acquire) || shared.is_session_cancelled();
        let mut backoff = Duration::from_secs(1);
        while !cancelled() {
            let result = (|| -> io::Result<()> {
                let listener = TcpListener::bind("127.0.0.1:0")?;
                listener.set_nonblocking(true)?;
                let forwarding = listener.local_addr()?;
                let mut control = Setup::new(address, &cancelled)?;
                let authentication = if let Some(path) = &self.config.tor_cookie {
                    let mut bytes = Vec::with_capacity(33);
                    std::fs::File::open(path)?
                        .take(33)
                        .read_to_end(&mut bytes)?;
                    if bytes.len() != 32 {
                        return Err(invalid("Tor cookie must contain 32 bytes"));
                    }
                    format!("AUTHENTICATE {}\r\n", bytes.to_lower_hex_string())
                } else {
                    "AUTHENTICATE\r\n".to_owned()
                };
                control.write(authentication.as_bytes())?;
                reply(&mut control)?;
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
                            let id = NEXT_ANONYMOUS
                                .try_update(Ordering::AcqRel, Ordering::Acquire, |id| {
                                    id.checked_add(1)
                                })
                                .map_err(|_| invalid("Tor inbound identity exhausted"))?;
                            crate::listener::admit_inbound(
                                stream,
                                PeerEndpoint::new(PeerAddress::AnonymousTor(id), 0),
                                shared,
                            );
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            pause(&cancelled, POLL);
                        }
                        Err(error) => return Err(error),
                    }
                }
                // No Detach flag: closing the control socket removes only this service.
                Ok(())
            })();
            *self.local_onion.write() = None;
            // Forwarded connections belong to the lost service, but outbound Tor circuits
            // use the independently configured SOCKS route and need not be retired.
            for session in shared.peer_table.sessions() {
                if matches!(session.addr.address(), PeerAddress::AnonymousTor(_)) {
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
