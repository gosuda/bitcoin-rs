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
mod tests {
    use super::*;
    use bitcoin_rs_primitives::endpoint::tor_v3_payload;
    use std::net::{IpAddr, Ipv4Addr};

    fn tor_endpoint() -> PeerEndpoint {
        PeerEndpoint::TorV3 {
            key: [3u8; 32],
            port: 8333,
        }
    }

    #[test]
    fn parse_format_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        for endpoint in [
            PeerEndpoint::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333)),
            PeerEndpoint::Ip("[::1]:8333".parse::<SocketAddr>()?),
            tor_endpoint(),
            PeerEndpoint::I2p {
                hash: [5u8; 32],
                port: 7656,
            },
        ] {
            let text = format_endpoint(endpoint);
            assert_eq!(parse_endpoint(&text), Some(endpoint), "{text}");
        }
        Ok(())
    }

    #[test]
    fn parse_rejects_bad_tor_checksum_and_payload() {
        let mut payload = tor_v3_payload(&[3u8; 32]);
        payload[32] ^= 1;
        let bad = format!(
            "{}.onion:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&payload)
        );
        assert_eq!(parse_endpoint(&bad), None);
        assert_eq!(parse_endpoint("abc.onion:8333"), None);
        let good = format_endpoint(tor_endpoint());
        assert_eq!(parse_endpoint(&good.replace("8333", "0")), None);
        assert_eq!(parse_endpoint(&good.to_uppercase()), None);
        assert_eq!(
            parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(51))),
            None
        );
        assert_eq!(
            parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(53))),
            None
        );
        assert_eq!(
            parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(52))),
            Some(PeerEndpoint::I2p {
                hash: [0u8; 32],
                port: 8333
            })
        );
    }

    #[test]
    fn classification_matrix_valid_cases() {
        let good_tor = format_endpoint(tor_endpoint());
        let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

        assert!(matches!(
            classify_endpoint(&good_tor),
            ClassifiedEndpoint::Valid(PeerEndpoint::TorV3 { port: 8333, .. })
        ));
        assert_eq!(
            classify_endpoint(&good_i2p),
            ClassifiedEndpoint::Valid(PeerEndpoint::I2p {
                hash: [0u8; 32],
                port: 8333
            })
        );
        assert_eq!(
            classify_endpoint("127.0.0.1:8333"),
            ClassifiedEndpoint::Valid(PeerEndpoint::Ip(SocketAddr::from(([127, 0, 0, 1], 8333))))
        );
    }

    #[test]
    fn classification_matrix_invalid_overlay_cases() {
        let good_tor = format_endpoint(tor_endpoint());
        let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

        let mut bad_payload = tor_v3_payload(&[3u8; 32]);
        bad_payload[32] ^= 1;
        let bad_checksum_onion = format!(
            "{}.onion:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&bad_payload)
        );

        let wrong_len_i2p_51 = format!("{}.b32.i2p:8333", "a".repeat(51));
        let wrong_len_i2p_53 = format!("{}.b32.i2p:8333", "a".repeat(53));
        let missing_port_onion = format!(
            "{}.onion",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );
        let missing_port_i2p = format!("{}.b32.i2p", "a".repeat(52));
        let malformed_port_onion = format!(
            "{}.onion:notaport",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );
        let zero_port_onion = good_tor.replace("8333", "0");
        let overflow_port_onion = format!(
            "{}.onion:99999",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );

        let uppercase_onion = good_tor.to_uppercase();
        let mixedcase_onion = format!(
            "{}.ONION:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );
        let uppercase_i2p = good_i2p.to_uppercase();
        let mixedcase_i2p = format!("{}.B32.I2P:8333", "a".repeat(52));
        let trailing_dot_onion = format!(
            "{}.onion.:8333",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );
        let trailing_dot_no_port = format!(
            "{}.onion.",
            bitcoin_rs_primitives::endpoint::base32_encode(&tor_v3_payload(&[3u8; 32]))
        );
        let trailing_dot_i2p = format!("{}.b32.i2p.:8333", "a".repeat(52));
        let trailing_dot_i2p_no_port = format!("{}.b32.i2p.", "a".repeat(52));

        let invalid_targets = [
            bad_checksum_onion.as_str(),
            "abc.onion:8333",
            wrong_len_i2p_51.as_str(),
            wrong_len_i2p_53.as_str(),
            missing_port_onion.as_str(),
            missing_port_i2p.as_str(),
            malformed_port_onion.as_str(),
            zero_port_onion.as_str(),
            overflow_port_onion.as_str(),
            uppercase_onion.as_str(),
            mixedcase_onion.as_str(),
            uppercase_i2p.as_str(),
            mixedcase_i2p.as_str(),
            trailing_dot_onion.as_str(),
            trailing_dot_no_port.as_str(),
            trailing_dot_i2p.as_str(),
            trailing_dot_i2p_no_port.as_str(),
            "foo.i2p:8333",
            "foo.i2p",
            "FOO.I2P:8333",
            "foo.i2p.:8333",
            "foo.i2p.",
            "b32.i2p:8333",
            "b32.i2p",
            "B32.I2P:8333",
            "b32.i2p.:8333",
            "onion.:8333",
            "onion.",
            "ONION.:8333",
            "i2p.:8333",
            "i2p.",
            "I2P.:8333",
        ];

        for rejected in invalid_targets {
            assert_eq!(
                classify_endpoint(rejected),
                ClassifiedEndpoint::InvalidOverlay,
                "invalid overlay target must classify as InvalidOverlay: {rejected}"
            );
            assert_eq!(parse_endpoint(rejected), None);
        }
    }

    #[test]
    fn classification_matrix_ordinary_hostnames() {
        for ordinary in [
            "seed.bitcoin.sipa.be:8333",
            "node.example.com:8333",
            "onion.com:8333",
            "fakeb32.i2p.org:8333",
            "onion:8333",
            "onion",
            "i2p:8333",
            "i2p",
        ] {
            assert_eq!(
                classify_endpoint(ordinary),
                ClassifiedEndpoint::NonOverlay,
                "ordinary hostname must classify as NonOverlay: {ordinary}"
            );
            assert_eq!(parse_endpoint(ordinary), None);
        }
    }

    #[test]
    fn i2p_port_zero_is_valid_but_tor_and_ip_are_not() {
        let i2p_zero = format!("{}.b32.i2p:0", "a".repeat(52));
        assert_eq!(
            classify_endpoint(&i2p_zero),
            ClassifiedEndpoint::Valid(PeerEndpoint::I2p {
                hash: [0u8; 32],
                port: 0
            })
        );
        assert_eq!(
            parse_endpoint(&i2p_zero),
            Some(PeerEndpoint::I2p {
                hash: [0u8; 32],
                port: 0
            })
        );

        let tor_zero = format_endpoint(tor_endpoint()).replace("8333", "0");
        assert_eq!(
            classify_endpoint(&tor_zero),
            ClassifiedEndpoint::InvalidOverlay
        );
        assert_eq!(parse_endpoint(&tor_zero), None);
        assert_eq!(parse_endpoint("127.0.0.1:0"), None);
    }

    #[test]
    fn addrv2_accepts_i2p_port_zero_only() {
        let i2p_zero = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::I2p([7u8; 32]),
            port: 0,
        };
        assert_eq!(
            endpoint_from_addrv2(&i2p_zero),
            Some(PeerEndpoint::I2p {
                hash: [7u8; 32],
                port: 0
            })
        );
        for addr in [AddrV2::Ipv4(Ipv4Addr::LOCALHOST), AddrV2::TorV3([3u8; 32])] {
            assert_eq!(
                endpoint_from_addrv2(&AddrV2Message {
                    time: 1,
                    services: ServiceFlags::NETWORK,
                    addr,
                    port: 0,
                }),
                None
            );
        }
    }

    #[test]
    fn addrv2_round_trip_and_rejections() {
        for endpoint in [
            PeerEndpoint::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333)),
            tor_endpoint(),
            PeerEndpoint::I2p {
                hash: [5u8; 32],
                port: 7656,
            },
        ] {
            let row = endpoint_to_addrv2(endpoint, 1, ServiceFlags::NETWORK);
            assert_eq!(endpoint_from_addrv2(&row), Some(endpoint));
        }
        let torv2 = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::TorV2([0u8; 10]),
            port: 8333,
        };
        assert_eq!(endpoint_from_addrv2(&torv2), None);
        let unknown = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Unknown(99, vec![1, 2, 3]),
            port: 8333,
        };
        assert_eq!(endpoint_from_addrv2(&unknown), None);
    }

    #[test]
    fn overlay_dial_is_unavailable_without_fallback() {
        for endpoint in [
            tor_endpoint(),
            PeerEndpoint::I2p {
                hash: [1u8; 32],
                port: 8333,
            },
        ] {
            let Err(error) =
                connect_peer_stream(endpoint, &DialRoutes::default(), Duration::from_millis(10))
            else {
                panic!("overlay must not dial");
            };
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(!error.counts_as_peer_failure());
        }
    }

    #[test]
    fn dead_onion_proxy_is_transport_not_peer_failure() -> Result<(), Box<dyn std::error::Error>> {
        let routes = DialRoutes {
            onion: Some("127.0.0.1:1".parse()?),
            ..DialRoutes::default()
        };
        let Err(error) = connect_peer_stream(tor_endpoint(), &routes, Duration::from_secs(2))
        else {
            panic!("dead proxy must fail the dial");
        };
        assert!(matches!(error, DialFailure::Transport(_)));
        assert!(!error.counts_as_peer_failure());
        Ok(())
    }

    #[test]
    fn onlynet_refusal_is_transport_not_peer_failure() {
        let routes = DialRoutes {
            onlynet: vec![NetworkLabel::Ipv4],
            ..DialRoutes::default()
        };
        let Err(error) = connect_peer_stream(tor_endpoint(), &routes, Duration::from_millis(10))
        else {
            panic!("onlynet must refuse the dial");
        };
        assert!(matches!(error, DialFailure::Transport(_)));
        assert!(!error.counts_as_peer_failure());
    }

    #[test]
    fn route_table_denial_prefilters_unroutable_endpoints() {
        let ip = PeerEndpoint::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333));
        let i2p = PeerEndpoint::I2p {
            hash: [7u8; 32],
            port: 8333,
        };
        let open = RouteTable::default();
        assert_eq!(open.denial(&ip), None);
        assert_eq!(
            open.denial(&tor_endpoint()),
            Some(RouteDenial::NoOnionRoute)
        );
        assert_eq!(open.denial(&i2p), Some(RouteDenial::NoI2pRoute));
        let onion_only = RouteTable {
            onlynet: vec![NetworkLabel::Onion],
            ..RouteTable::default()
        };
        assert_eq!(onion_only.denial(&ip), Some(RouteDenial::NotInOnlynet));
    }

    #[test]
    fn direct_tcp_classifies_only_refusal_as_peer_unreachable()
    -> Result<(), Box<dyn std::error::Error>> {
        let unused_port: SocketAddr = "127.0.0.1:1".parse()?;
        let Err(error) = connect_peer_stream(
            PeerEndpoint::Ip(unused_port),
            &DialRoutes::default(),
            Duration::from_millis(200),
        ) else {
            panic!("refused dial must fail");
        };
        match &error {
            DialFailure::PeerUnreachable(io_err) => {
                assert_eq!(io_err.kind(), io::ErrorKind::ConnectionRefused);
                assert!(
                    error.counts_as_peer_failure(),
                    "ConnectionRefused must count as peer failure"
                );
            }
            DialFailure::Transport(_) => {
                assert_ne!(error.kind(), io::ErrorKind::ConnectionRefused);
                assert!(
                    !error.counts_as_peer_failure(),
                    "Non-refusal must not count as peer failure"
                );
            }
        }

        let blackhole: SocketAddr = "192.0.2.1:8333".parse()?;
        let Err(error) = connect_peer_stream(
            PeerEndpoint::Ip(blackhole),
            &DialRoutes::default(),
            Duration::from_millis(1),
        ) else {
            panic!("timed out dial must fail");
        };
        match &error {
            DialFailure::Transport(_) => {
                assert_ne!(error.kind(), io::ErrorKind::ConnectionRefused);
                assert!(
                    !error.counts_as_peer_failure(),
                    "Timeout or network error must remain Transport failure"
                );
            }
            DialFailure::PeerUnreachable(io_err) => {
                assert_eq!(io_err.kind(), io::ErrorKind::ConnectionRefused);
                assert!(
                    error.counts_as_peer_failure(),
                    "ConnectionRefused must count as peer failure"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn overlay_netgroup_vectors() {
        assert_eq!(
            overlay_netgroup(EndpointHost::TorV3 { key: [0x21u8; 32] }),
            Some(vec![4, 0x2f])
        );
        assert_eq!(
            overlay_netgroup(EndpointHost::I2p { hash: [0x30u8; 32] }),
            Some(vec![5, 0x3f])
        );
        assert_eq!(
            overlay_netgroup(EndpointHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            None
        );
    }
}
