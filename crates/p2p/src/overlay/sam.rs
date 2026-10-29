//! IVNP SAM v3 STREAM session lifecycle, naming, connect, and accept.
use super::{
    Arc, AtomicBool, Connected, Duration, Instant, Ordering, OverlayTransport, PeerAddress,
    PeerEndpoint, SETUP_TIMEOUT, Setup, SocketAddr, cancelled_error, identity, invalid, io, pause,
};
use sha2::{Digest, Sha256};
pub(super) struct Session {
    id: String,
    pub(super) alive: Arc<AtomicBool>,
    pub(super) local_address: PeerEndpoint,
}
// run_sam alone publishes/removes session records and starts replacements.
// Each epoch has one irreversible alive marker, shared by streams and leases.
// An INVALID_ID only revokes the marker observed by that request; it never
// replaces a session or cancels peers by network. Ordinary lease teardown and
// the sync reconciler consume that revocation through PeerLease::is_cancelled.
fn hello(setup: &mut Setup<'_>) -> io::Result<()> {
    setup.write(b"HELLO VERSION MIN=3.1 MAX=3.3\n")?;
    let line = setup.line()?;
    if !line.starts_with("HELLO REPLY ")
        || field(&line, "RESULT") != Some("OK")
        || !matches!(field(&line, "VERSION"), Some("3.1" | "3.2" | "3.3"))
    {
        return Err(invalid("unsupported or malformed SAM negotiation"));
    }
    Ok(())
}
fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let mut matches = line
        .split_ascii_whitespace()
        .filter_map(|token| token.split_once('='))
        .filter(|(key, _)| *key == name);
    let (_, value) = matches.next()?;
    if matches.next().is_some() {
        None
    } else {
        Some(value)
    }
}
#[derive(Debug, thiserror::Error)]
#[error("SAM stream session no longer exists")]
struct InvalidSession;

fn retire_invalid_session(error: &io::Error, alive: &AtomicBool) {
    if matches!(error.get_ref(), Some(cause) if cause.is::<InvalidSession>()) {
        // The flag belongs to the session used by this request. A late reply
        // cannot revoke a replacement session's distinct flag.
        alive.store(false, Ordering::Release);
    }
}
fn status(setup: &mut Setup<'_>, prefix: &str) -> io::Result<String> {
    let line = setup.line()?;
    if !line.starts_with(prefix) || field(&line, "RESULT") != Some("OK") {
        let result = match field(&line, "RESULT") {
            Some("I2P_ERROR") => "I2P_ERROR",
            Some("DUPLICATED_DEST") => "DUPLICATED_DEST",
            Some("DUPLICATED_ID") => "DUPLICATED_ID",
            Some("INVALID_KEY") => "INVALID_KEY",
            Some("INVALID_ID") => "INVALID_ID",
            Some("CANT_REACH_PEER") => "CANT_REACH_PEER",
            Some("TIMEOUT") => "TIMEOUT",
            Some("KEY_NOT_FOUND") => "KEY_NOT_FOUND",
            _ => "malformed reply",
        };
        let message = format!("SAM {prefix}{result}");
        if prefix == "STREAM STATUS " && line.starts_with(prefix) && result == "INVALID_ID" {
            return Err(io::Error::new(io::ErrorKind::NotConnected, InvalidSession));
        }
        // Naming is part of dialing: an unresolved destination must reach the
        // same AddrMan attempt owner as an explicit stream refusal. Only the
        // documented naming miss qualifies; router errors and malformed replies
        // are still local failures, not evidence against the requested peer.
        if line.starts_with(prefix)
            && matches!(
                (prefix, result),
                ("STREAM STATUS ", "CANT_REACH_PEER" | "TIMEOUT")
                    | ("NAMING REPLY ", "KEY_NOT_FOUND")
            )
        {
            return Err(super::remote_failure(message));
        }
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, message));
    }
    Ok(line)
}
fn destination(text: &str) -> io::Result<PeerAddress> {
    Ok(PeerAddress::I2p(
        Sha256::digest(identity::public_destination(text)?).into(),
    ))
}

fn lookup(setup: &mut Setup<'_>, name: &str) -> io::Result<(String, PeerAddress)> {
    setup.write(format!("NAMING LOOKUP NAME={name}\n").as_bytes())?;
    let line = status(setup, "NAMING REPLY ")?;
    let public = field(&line, "VALUE").ok_or_else(|| invalid("SAM naming lacks destination"))?;
    Ok((public.to_owned(), destination(public)?))
}

impl OverlayTransport {
    fn sam_session(&self) -> io::Result<(String, Arc<AtomicBool>)> {
        let (id, alive) = self
            .sam
            .read()
            .as_ref()
            .map(|session| (session.id.clone(), Arc::clone(&session.alive)))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "IVNP SAM session unavailable")
            })?;
        if !alive.load(Ordering::Acquire) {
            return Err(cancelled_error());
        }
        Ok((id, alive))
    }
    pub(super) fn sam_lookup(
        &self,
        name: &str,
        port: u16,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<PeerEndpoint> {
        let (_, alive) = self.sam_session()?;
        let stop = || cancelled() || !alive.load(Ordering::Acquire);
        let mut setup = Setup::new(
            self.config.i2p_sam.ok_or_else(|| invalid("SAM disabled"))?,
            &stop,
        )?;
        hello(&mut setup)?;
        let (_, address) = lookup(&mut setup, name)?;
        if !alive.load(Ordering::Acquire) {
            return Err(cancelled_error());
        }
        Ok(PeerEndpoint::new(address, port))
    }
    pub(super) fn sam_connect(
        &self,
        endpoint: PeerEndpoint,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Connected> {
        self.sam_connect_until(
            endpoint,
            cancelled,
            Instant::now() + Duration::from_secs(80),
        )
    }
    fn sam_connect_until(
        &self,
        endpoint: PeerEndpoint,
        cancelled: &dyn Fn() -> bool,
        deadline: Instant,
    ) -> io::Result<Connected> {
        let (id, alive) = self.sam_session()?;
        let stop = || cancelled() || !alive.load(Ordering::Acquire);
        let address = self.config.i2p_sam.ok_or_else(|| invalid("SAM disabled"))?;
        let mut naming =
            Setup::new_until(address, &stop, deadline.min(Instant::now() + SETUP_TIMEOUT))?;
        hello(&mut naming)?;
        let (public, resolved) = lookup(&mut naming, &endpoint.address().to_string())?;
        if resolved != endpoint.address() {
            return Err(invalid(
                "SAM naming destination does not match requested identity",
            ));
        }
        drop(naming);
        let mut setup =
            Setup::new_until(address, &stop, deadline.min(Instant::now() + SETUP_TIMEOUT))?;
        hello(&mut setup)?;
        setup.deadline = deadline.min(Instant::now() + Duration::from_secs(60));
        // Connect to the validated public destination, not a second name lookup.
        setup.write(
            format!(
                "STREAM CONNECT ID={id} DESTINATION={} TO_PORT={} SILENT=false\n",
                public,
                endpoint.port()
            )
            .as_bytes(),
        )?;
        if let Err(error) = status(&mut setup, "STREAM STATUS ") {
            retire_invalid_session(&error, &alive);
            return Err(error);
        }
        setup.check()?;
        if !alive.load(Ordering::Acquire) {
            return Err(cancelled_error());
        }
        Ok(Connected {
            stream: setup.finish()?,
            alive: Some(alive),
        })
    }
    pub(super) fn run_sam(
        &self,
        address: SocketAddr,
        mut key: Option<String>,
        shared: &crate::listener::ConnectionShared,
        shutdown: &AtomicBool,
    ) {
        use bitcoin::secp256k1::rand::RngCore as _;
        let cancelled = || shutdown.load(Ordering::Acquire) || shared.is_session_cancelled();
        let mut backoff = Duration::from_secs(1);
        while !cancelled() {
            let result = (|| -> io::Result<()> {
                let mut control = Setup::new(address, &cancelled)?;
                hello(&mut control)?;
                if self.config.i2p_accept && key.is_none() {
                    control.write(b"DEST GENERATE SIGNATURE_TYPE=7\n")?;
                    let line = control.line()?;
                    if !line.starts_with("DEST REPLY ") {
                        return Err(invalid("SAM destination generation refused"));
                    }
                    let private = field(&line, "PRIV")
                        .ok_or_else(|| invalid("SAM destination lacks private key"))?;
                    key = Some(private.to_owned());
                }
                if let Some(private) = &key {
                    identity::create(
                        &self.config.identity_dir.join("i2p.key"),
                        private,
                        identity::Kind::I2p,
                    )?;
                }
                let id = format!(
                    "bitcoin-rs-{:016x}",
                    bitcoin::secp256k1::rand::thread_rng().next_u64()
                );
                control.deadline = Instant::now() + Duration::from_secs(120);
                control.write(
                    format!(
                        "SESSION CREATE STYLE=STREAM ID={id} DESTINATION={} TO_PORT={}\n",
                        key.as_deref().unwrap_or("TRANSIENT"),
                        self.config.port
                    )
                    .as_bytes(),
                )?;
                status(&mut control, "SESSION STATUS ")?;
                control.deadline = Instant::now() + SETUP_TIMEOUT;
                control.write(b"NAMING LOOKUP NAME=ME\n")?;
                let reply = status(&mut control, "NAMING REPLY ")?;
                let local = PeerEndpoint::new(
                    destination(
                        field(&reply, "VALUE")
                            .ok_or_else(|| invalid("SAM local destination missing"))?,
                    )?,
                    self.config.port,
                );
                let alive = Arc::new(AtomicBool::new(true));
                *self.sam.write() = Some(Session {
                    id: id.clone(),
                    alive: Arc::clone(&alive),
                    local_address: local,
                });
                let healthy_since = Instant::now();

                std::thread::scope(|scope| {
                    let accept = self
                        .config
                        .i2p_accept
                        .then(|| scope.spawn(|| self.accept_sam(&id, &alive, shared, &cancelled)));
                    let monitored = (|| -> io::Result<()> {
                        let stop = || cancelled() || !alive.load(Ordering::Acquire);
                        while !stop() {
                            control.deadline = Instant::now() + SETUP_TIMEOUT;
                            control.write(b"PING bitcoin-rs\n")?;
                            if control.line()? != "PONG bitcoin-rs" {
                                return Err(invalid("SAM control heartbeat failed"));
                            }
                            if healthy_since.elapsed() >= Duration::from_secs(60) {
                                backoff = Duration::from_secs(1);
                            }
                            pause(&stop, Duration::from_secs(1));
                        }
                        if !alive.load(Ordering::Acquire) && !cancelled() {
                            Err(io::Error::new(io::ErrorKind::NotConnected, InvalidSession))
                        } else {
                            Ok(())
                        }
                    })();
                    alive.store(false, Ordering::Release);
                    if let Some(accept) = accept {
                        let _ = accept.join();
                    }
                    monitored
                })
            })();
            // This worker alone unpublishes the epoch and wakes its leases.
            // Connect/accept failures may revoke admission through `alive`, but
            // cannot remove sessions or cancel connections of another epoch.
            let retired = self.sam.write().take();
            if let Some(session) = retired {
                session.alive.store(false, Ordering::Release);
                shared.peer_table.cancel_transport_epoch(&session.alive);
            }
            if let Err(error) = result {
                if !cancelled() {
                    tracing::warn!(%error, "IVNP SAM unavailable; retiring streams and retrying");
                }
            }
            pause(&cancelled, backoff);
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }
    fn accept_sam(
        &self,
        id: &str,
        alive: &Arc<AtomicBool>,
        shared: &crate::listener::ConnectionShared,
        cancelled: &dyn Fn() -> bool,
    ) {
        let stop = || cancelled() || !alive.load(Ordering::Acquire);
        while !stop() {
            let result = (|| -> io::Result<()> {
                let mut setup = Setup::new(
                    self.config.i2p_sam.ok_or_else(|| invalid("SAM disabled"))?,
                    &stop,
                )?;
                hello(&mut setup)?;
                setup.write(format!("STREAM ACCEPT ID={id} SILENT=false\n").as_bytes())?;
                // IVNP sends STATUS only after accepting a circuit. This is a listener wait,
                // not an unbounded setup operation; cancellation still polls every 100ms.
                setup.deadline = Instant::now() + Duration::from_hours(24);
                if let Err(error) = status(&mut setup, "STREAM STATUS ") {
                    retire_invalid_session(&error, alive);
                    return Err(error);
                }
                setup.deadline = Instant::now() + SETUP_TIMEOUT;
                let metadata = setup.line()?;
                let public = metadata
                    .split_ascii_whitespace()
                    .next()
                    .ok_or_else(|| invalid("SAM missing remote destination"))?;
                let remote = destination(public)?;
                let port = field(&metadata, "FROM_PORT")
                    .ok_or_else(|| invalid("SAM missing remote port"))?
                    .parse::<u16>()
                    .map_err(|_| invalid("invalid SAM remote port"))?;
                crate::listener::admit_inbound_with_epoch(
                    setup.finish()?,
                    PeerEndpoint::new(remote, port),
                    shared,
                    Some(Arc::clone(alive)),
                );
                Ok(())
            })();
            if let Err(error) = result {
                if !stop() {
                    tracing::warn!(%error, "IVNP inbound stream rejected");
                    pause(&stop, Duration::from_secs(1));
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
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
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < end =>
                    {
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
}
