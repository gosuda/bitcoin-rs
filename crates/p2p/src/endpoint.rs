//! P2P-owned endpoint parsing, formatting, BIP155 conversion, and dialing.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin_rs_primitives::endpoint::{base32_decode, tor_v3_key_from_payload, tor_v3_payload};
use bitcoin_rs_primitives::{EndpointHost, NetworkLabel, PeerEndpoint};
use sha2::{Digest, Sha256};

use crate::sam::SamSession;
use crate::socks::{SocksTarget, socks_connect};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportRemote(SocketAddr);

impl TransportRemote {
    #[must_use]
    pub const fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }

    #[must_use]
    pub const fn socket_addr(self) -> SocketAddr {
        self.0
    }
}

impl std::fmt::Display for TransportRemote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[must_use]
pub fn accepted_ip_identity(remote: SocketAddr) -> PeerEndpoint {
    PeerEndpoint::Ip(remote)
}

#[must_use]
pub fn dialed_ip_identity(addr: SocketAddr) -> PeerEndpoint {
    PeerEndpoint::Ip(addr)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassifiedEndpoint {
    Valid(PeerEndpoint),
    InvalidOverlay,
    NonOverlay,
}

#[must_use]
pub(crate) fn is_reserved_overlay_host(host: &str) -> bool {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let had_trailing_dot = unbracketed.ends_with('.');
    let trimmed = unbracketed.trim_end_matches('.');
    let label = match trimmed.rsplit_once('.') {
        Some((_, last_label)) => last_label,
        None if had_trailing_dot => trimmed,
        None => return false,
    };
    label.eq_ignore_ascii_case("onion") || label.eq_ignore_ascii_case("i2p")
}

#[must_use]
pub fn classify_endpoint(text: &str) -> ClassifiedEndpoint {
    if let Ok(socket) = text.parse::<SocketAddr>() {
        if socket.port() == 0 {
            return ClassifiedEndpoint::NonOverlay;
        }
        return ClassifiedEndpoint::Valid(PeerEndpoint::Ip(socket));
    }

    let (host, port_text) = text
        .rsplit_once(':')
        .map_or((text, None), |(h, p)| (h, Some(p)));

    let first_host = text.split_once(':').map_or(text, |(h, _)| h);
    let is_overlay = is_reserved_overlay_host(host)
        || is_reserved_overlay_host(first_host)
        || is_reserved_overlay_host(text);

    if !is_overlay {
        return ClassifiedEndpoint::NonOverlay;
    }

    let Some(port_str) = port_text else {
        return ClassifiedEndpoint::InvalidOverlay;
    };
    let Ok(port) = port_str.parse::<u16>() else {
        return ClassifiedEndpoint::InvalidOverlay;
    };

    if let Some(onion) = host.strip_suffix(".onion") {
        if port == 0 {
            return ClassifiedEndpoint::InvalidOverlay;
        }
        if onion.len() != 56 {
            return ClassifiedEndpoint::InvalidOverlay;
        }
        let Some(payload) = base32_decode(onion) else {
            return ClassifiedEndpoint::InvalidOverlay;
        };
        let Some(key) = tor_v3_key_from_payload(&payload) else {
            return ClassifiedEndpoint::InvalidOverlay;
        };
        return ClassifiedEndpoint::Valid(PeerEndpoint::TorV3 { key, port });
    }

    if let Some(b32) = host.strip_suffix(".b32.i2p") {
        if b32.len() != 52 {
            return ClassifiedEndpoint::InvalidOverlay;
        }
        let Some(payload) = base32_decode(b32) else {
            return ClassifiedEndpoint::InvalidOverlay;
        };
        if payload.len() != 32 {
            return ClassifiedEndpoint::InvalidOverlay;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload);
        return ClassifiedEndpoint::Valid(PeerEndpoint::I2p { hash, port });
    }

    ClassifiedEndpoint::InvalidOverlay
}

#[must_use]
pub fn parse_endpoint(text: &str) -> Option<PeerEndpoint> {
    match classify_endpoint(text) {
        ClassifiedEndpoint::Valid(endpoint) => Some(endpoint),
        ClassifiedEndpoint::InvalidOverlay | ClassifiedEndpoint::NonOverlay => None,
    }
}

#[must_use]
pub fn display_endpoint(endpoint: Option<PeerEndpoint>) -> String {
    endpoint.map_or_else(|| "unknown".to_owned(), |endpoint| endpoint.to_string())
}

#[must_use]
pub fn format_endpoint(endpoint: PeerEndpoint) -> String {
    endpoint.to_string()
}

/// Convert a BIP155 `addrv2` row to a typed endpoint.
/// BIP155 ids 1/2 (IP) and 4/5 (`TorV3`/`I2P`) are accepted; `TorV2`,
#[must_use]
pub fn endpoint_from_addrv2(message: &AddrV2Message) -> Option<PeerEndpoint> {
    let port = message.port;
    if port == 0 && !matches!(message.addr, AddrV2::I2p(_)) {
        return None;
    }
    match message.addr {
        AddrV2::Ipv4(ip) => Some(PeerEndpoint::Ip(SocketAddr::new(ip.into(), port))),
        AddrV2::Ipv6(ip) => Some(PeerEndpoint::Ip(SocketAddr::new(ip.into(), port))),
        AddrV2::TorV3(key) => Some(PeerEndpoint::TorV3 { key, port }),
        AddrV2::I2p(hash) => Some(PeerEndpoint::I2p { hash, port }),
        _ => None,
    }
}

/// Convert a typed endpoint to a BIP155 `addrv2` row.
#[must_use]
pub fn endpoint_to_addrv2(
    endpoint: PeerEndpoint,
    time: u32,
    services: ServiceFlags,
) -> AddrV2Message {
    let (addr, port) = match endpoint {
        PeerEndpoint::Ip(SocketAddr::V4(socket)) => (AddrV2::Ipv4(*socket.ip()), socket.port()),
        PeerEndpoint::Ip(SocketAddr::V6(socket)) => (AddrV2::Ipv6(*socket.ip()), socket.port()),
        PeerEndpoint::TorV3 { key, port } => (AddrV2::TorV3(key), port),
        PeerEndpoint::I2p { hash, port } => (AddrV2::I2p(hash), port),
    };
    AddrV2Message {
        time,
        services,
        addr,
        port,
    }
}

#[must_use]
pub const fn addrv2_gossip_enabled(
    endpoint: PeerEndpoint,
    tor_enabled: bool,
    i2p_enabled: bool,
) -> bool {
    match endpoint {
        PeerEndpoint::Ip(_) => true,
        PeerEndpoint::TorV3 { .. } => tor_enabled,
        PeerEndpoint::I2p { .. } => i2p_enabled,
    }
}

/// Canonical `AddrMan` netgroup for an endpoint host (not the BIP155 tag).
#[must_use]
pub fn overlay_netgroup(host: EndpointHost) -> Option<Vec<u8>> {
    match host {
        EndpointHost::TorV3 { key } => Some(vec![4, key[0] | 0x0f]),
        EndpointHost::I2p { hash } => Some(vec![5, hash[0] | 0x0f]),
        EndpointHost::Ip(_) => None,
    }
}

#[must_use]
pub fn anonymous_netgroup(connection_id: crate::ConnectionId) -> Vec<u8> {
    let digest = Sha256::digest(connection_id.get().to_le_bytes());
    vec![3, digest[0], digest[1]]
}

#[derive(Clone, Debug, Default)]
pub struct DialRoutes {
    pub proxy: Option<SocketAddr>,
    pub onion: Option<SocketAddr>,
    pub proxy_randomize_credentials: bool,
    pub sam_session: Option<Arc<SamSession>>,
    pub onlynet: Vec<NetworkLabel>,
}

impl DialRoutes {
    #[must_use]
    pub fn tor_enabled(&self) -> bool {
        self.onion.is_some() || self.proxy.is_some()
    }

    #[must_use]
    pub fn i2p_enabled(&self) -> bool {
        self.sam_session.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDenial {
    NotInOnlynet,
    NoOnionRoute,
    NoI2pRoute,
}

#[derive(Clone, Debug, Default)]
pub struct RouteTable {
    pub onlynet: Vec<NetworkLabel>,
    pub proxy: Option<SocketAddr>,
    pub onion: Option<SocketAddr>,
    pub sam_session: Option<Arc<SamSession>>,
}

impl RouteTable {
    #[must_use]
    pub fn from_routes(routes: &DialRoutes) -> Self {
        Self {
            onlynet: routes.onlynet.clone(),
            proxy: routes.proxy,
            onion: routes.onion,
            sam_session: routes.sam_session.clone(),
        }
    }

    #[must_use]
    pub fn denial(&self, endpoint: &PeerEndpoint) -> Option<RouteDenial> {
        if !self.onlynet.is_empty() && !self.onlynet.contains(&endpoint.net()) {
            return Some(RouteDenial::NotInOnlynet);
        }
        match endpoint {
            PeerEndpoint::Ip(_) => None,
            PeerEndpoint::TorV3 { .. } => {
                if self.onion.is_some() || self.proxy.is_some() {
                    None
                } else {
                    Some(RouteDenial::NoOnionRoute)
                }
            }
            PeerEndpoint::I2p { .. } => {
                if self.sam_session.is_some() {
                    None
                } else {
                    Some(RouteDenial::NoI2pRoute)
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum DialFailure {
    Transport(io::Error),
    PeerUnreachable(io::Error),
}

impl DialFailure {
    #[must_use]
    pub const fn counts_as_peer_failure(&self) -> bool {
        matches!(self, Self::PeerUnreachable(_))
    }

    #[must_use]
    pub fn kind(&self) -> io::ErrorKind {
        match self {
            Self::Transport(error) | Self::PeerUnreachable(error) => error.kind(),
        }
    }

    #[must_use]
    pub fn into_io(self) -> io::Error {
        match self {
            Self::Transport(error) | Self::PeerUnreachable(error) => error,
        }
    }
}

impl std::fmt::Display for DialFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "transport failure: {error}"),
            Self::PeerUnreachable(error) => write!(f, "peer unreachable: {error}"),
        }
    }
}

impl std::error::Error for DialFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) | Self::PeerUnreachable(error) => Some(error),
        }
    }
}

impl From<io::Error> for DialFailure {
    fn from(error: io::Error) -> Self {
        Self::Transport(error)
    }
}

pub fn connect_peer_stream(
    endpoint: PeerEndpoint,
    routes: &DialRoutes,
    timeout: Duration,
) -> Result<TcpStream, DialFailure> {
    if !routes.onlynet.is_empty() && !routes.onlynet.contains(&endpoint.net()) {
        return Err(DialFailure::Transport(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dial refused: endpoint network is not in onlynet",
        )));
    }
    match endpoint {
        PeerEndpoint::Ip(addr) => match routes.proxy {
            Some(proxy) => socks_connect(
                proxy,
                &SocksTarget::Ip(addr),
                routes.proxy_randomize_credentials,
                timeout,
            ),
            None => match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => Ok(stream),
                Err(error) => Err(match error.kind() {
                    io::ErrorKind::ConnectionRefused => DialFailure::PeerUnreachable(error),
                    _ => DialFailure::Transport(error),
                }),
            },
        },
        PeerEndpoint::TorV3 { key, port } => {
            let Some(proxy) = routes.onion.or(routes.proxy) else {
                return Err(DialFailure::Transport(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "overlay transport unavailable: no onion proxy route is configured",
                )));
            };
            let host = format!(
                "{}.onion",
                bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&key))
            );
            debug_assert_eq!(host.len(), 62);
            socks_connect(proxy, &SocksTarget::Domain(host, port), true, timeout)
        }
        PeerEndpoint::I2p { hash, port } => {
            let Some(session) = &routes.sam_session else {
                return Err(DialFailure::Transport(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "overlay transport unavailable: no I2P SAM session is configured",
                )));
            };
            session.connect(hash, port)
        }
    }
}

#[cfg(test)]
mod tests;
