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
mod tests;
