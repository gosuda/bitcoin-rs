//! Opt-in transport setup. Successful streams enter the ordinary P2P session owner.
use bitcoin_rs_primitives::{PeerAddress, PeerEndpoint, PeerNetwork};
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
mod tests;
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
        fn label(network: PeerNetwork) -> bitcoin_rs_primitives::NetworkLabel {
            use bitcoin_rs_primitives::NetworkLabel as Label;
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
                    socks(
                        proxy,
                        endpoint,
                        self.config.randomize_credentials,
                        cancelled,
                    )
                } else {
                    TcpStream::connect_timeout(
                        &endpoint
                            .socket_addr()
                            .ok_or_else(|| invalid("missing IP socket"))?,
                        SETUP_TIMEOUT,
                    )
                }
            }
            PeerAddress::Onion(_) => socks(
                self.config
                    .onion_proxy
                    .ok_or_else(|| invalid("onion route disabled"))?,
                endpoint,
                self.config.randomize_credentials,
                cancelled,
            ),
            PeerAddress::I2p(_) => return self.sam_connect(endpoint, cancelled),
        }?;
        Ok(Connected {
            stream,
            alive: None,
        })
    }

    #[expect(
        clippy::case_sensitive_file_extension_comparisons,
        reason = "These normalized DNS suffixes identify protocols, not filesystem extensions"
    )]
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
        shutdown: &Arc<AtomicBool>,
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
        let mut workers = Vec::new();
        if let Some(address) = self.config.i2p_sam
            && self.config.allows(PeerNetwork::I2p)
        {
            let owner = Arc::clone(self);
            let shared = shared.clone();
            let shutdown = Arc::clone(shutdown);
            workers.push(
                std::thread::Builder::new()
                    .name("bitcoin-rs-ivnp-sam".into())
                    .spawn(move || {
                        owner.run_sam(address, i2p_key, &shared, &shutdown);
                        Ok(())
                    })?,
            );
        }
        if let Some(address) = self.config.tor_control {
            let owner = Arc::clone(self);
            let shared = shared.clone();
            let tor_shutdown = Arc::clone(shutdown);
            match std::thread::Builder::new()
                .name("bitcoin-rs-tor-control".into())
                .spawn(move || {
                    owner.run_tor(address, tor_key, &shared, &tor_shutdown);
                    Ok(())
                }) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    shutdown.store(true, Ordering::Release);
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

fn socks(
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

fn pause(cancelled: &dyn Fn() -> bool, delay: Duration) {
    let deadline = Instant::now() + delay;
    while !cancelled() && Instant::now() < deadline {
        std::thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}
