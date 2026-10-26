//! IVNP SAM v3 STREAM session lifecycle, naming, connect, and accept.
use super::{
    Arc, AtomicBool, Connected, Duration, Instant, Ordering, OverlayTransport, PeerAddress,
    PeerEndpoint, PeerNetwork, SETUP_TIMEOUT, Setup, SocketAddr, cancelled_error, identity,
    invalid, io, pause, retire,
};
use sha2::{Digest, Sha256};
pub(super) struct Session {
    id: String,
    alive: Arc<AtomicBool>,
}
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
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SAM {prefix}{result}"),
        ));
    }
    Ok(line)
}
fn destination(text: &str) -> io::Result<PeerAddress> {
    Ok(PeerAddress::I2p(
        Sha256::digest(identity::public_destination(text)?).into(),
    ))
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
        setup.write(format!("NAMING LOOKUP NAME={name}\n").as_bytes())?;
        let line = status(&mut setup, "NAMING REPLY ")?;
        if !alive.load(Ordering::Acquire) {
            return Err(cancelled_error());
        }
        Ok(PeerEndpoint::new(
            destination(
                field(&line, "VALUE").ok_or_else(|| invalid("SAM naming lacks destination"))?,
            )?,
            port,
        ))
    }
    pub(super) fn sam_connect(
        &self,
        endpoint: PeerEndpoint,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Connected> {
        let (id, alive) = self.sam_session()?;
        let stop = || cancelled() || !alive.load(Ordering::Acquire);
        let mut setup = Setup::new(
            self.config.i2p_sam.ok_or_else(|| invalid("SAM disabled"))?,
            &stop,
        )?;
        hello(&mut setup)?;
        setup.deadline = Instant::now() + Duration::from_secs(60);
        // IVNP resolves base32 names inside the router; no system DNS is involved.
        setup.write(
            format!(
                "STREAM CONNECT ID={id} DESTINATION={} TO_PORT={} SILENT=false\n",
                endpoint.address(),
                endpoint.port()
            )
            .as_bytes(),
        )?;
        status(&mut setup, "STREAM STATUS ")?;
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
                });
                if self.config.i2p_accept {
                    *self.local_i2p.write() = Some(local);
                }
                let healthy_since = Instant::now();

                std::thread::scope(|scope| {
                    let accept = self
                        .config
                        .i2p_accept
                        .then(|| scope.spawn(|| self.accept_sam(&id, &alive, shared, &cancelled)));
                    let monitored = (|| -> io::Result<()> {
                        while !cancelled() {
                            control.deadline = Instant::now() + SETUP_TIMEOUT;
                            control.write(b"PING bitcoin-rs\n")?;
                            if control.line()? != "PONG bitcoin-rs" {
                                return Err(invalid("SAM control heartbeat failed"));
                            }
                            if healthy_since.elapsed() >= Duration::from_secs(60) {
                                backoff = Duration::from_secs(1);
                            }
                            pause(&cancelled, Duration::from_secs(1));
                        }
                        Ok(())
                    })();
                    alive.store(false, Ordering::Release);
                    if let Some(accept) = accept {
                        let _ = accept.join();
                    }
                    monitored
                })
            })();
            let retired = self.sam.write().take();
            if let Some(session) = retired {
                session.alive.store(false, Ordering::Release);
            }
            *self.local_i2p.write() = None;
            retire(&shared.peer_table, PeerNetwork::I2p);
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
                status(&mut setup, "STREAM STATUS ")?;
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
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::TcpListener;

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
