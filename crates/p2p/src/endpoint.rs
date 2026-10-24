//! P2P-owned endpoint parsing, formatting, BIP155 conversion, and dialing.
//!
//! Only [`connect_peer_stream`] matches on transport variants. Every other
//! caller treats [`PeerEndpoint`] as opaque identity.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin_rs_primitives::endpoint::{base32_decode, tor_v3_key_from_payload};
use bitcoin_rs_primitives::{EndpointHost, PeerEndpoint};
use sha2::{Digest, Sha256};

/// Socket that actually carried a connection. This is socket accounting
/// (`addrbind`, local/remote socket) only; it is never peer identity and
/// has no conversion to [`PeerEndpoint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportRemote(SocketAddr);

impl TransportRemote {
    /// Wrap the socket a connection was accepted on / dialed to.
    #[must_use]
    pub const fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }

    /// The underlying socket, for `addrbind` reporting and socket accounting.
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

/// Identity assigned to a direct-IP inbound accept: the remote socket is
/// the logical peer for IP transport.
#[must_use]
pub fn accepted_ip_identity(remote: SocketAddr) -> PeerEndpoint {
    PeerEndpoint::Ip(remote)
}

/// Identity assigned to a dialed IP endpoint.
#[must_use]
pub fn dialed_ip_identity(addr: SocketAddr) -> PeerEndpoint {
    PeerEndpoint::Ip(addr)
}

/// Parse a textual endpoint: `host:port` for IP, `<56>.onion:port` for
/// Tor v3, or `<52>.b32.i2p:port` for I2P. Overlay names are validated
/// locally and never resolved through system DNS.
#[must_use]
pub fn parse_endpoint(text: &str) -> Option<PeerEndpoint> {
    if let Ok(socket) = text.parse::<SocketAddr>() {
        if socket.port() == 0 {
            return None;
        }
        return Some(PeerEndpoint::Ip(socket));
    }
    let (host, port_text) = text.rsplit_once(':')?;
    let port: u16 = port_text.parse().ok()?;
    if port == 0 {
        return None;
    }
    if let Some(onion) = host.strip_suffix(".onion") {
        if onion.len() != 56 {
            return None;
        }
        let payload = base32_decode(onion)?;
        let key = tor_v3_key_from_payload(&payload)?;
        return Some(PeerEndpoint::TorV3 { key, port });
    }
    if let Some(b32) = host.strip_suffix(".b32.i2p") {
        if b32.len() != 52 {
            return None;
        }
        let payload = base32_decode(b32)?;
        if payload.len() != 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload);
        return Some(PeerEndpoint::I2p { hash, port });
    }
    None
}

/// Log/report form of an optional endpoint: the endpoint or `unknown`.
#[must_use]
pub fn display_endpoint(endpoint: Option<PeerEndpoint>) -> String {
    endpoint.map_or_else(|| "unknown".to_owned(), |endpoint| endpoint.to_string())
}

/// Canonical textual form of an endpoint (inverse of [`parse_endpoint`]).
#[must_use]
pub fn format_endpoint(endpoint: PeerEndpoint) -> String {
    endpoint.to_string()
}

/// Convert a BIP155 `addrv2` row to a typed endpoint.
///
/// BIP155 ids 1/2 (IP) and 4/5 (`TorV3`/`I2P`) are accepted; `TorV2`,
/// CJDNS, and unknown networks are rejected.
#[must_use]
pub fn endpoint_from_addrv2(message: &AddrV2Message) -> Option<PeerEndpoint> {
    let port = message.port;
    if port == 0 {
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

/// Whether gossip may carry this endpoint on `addrv2` in this slice: no
/// overlay transport is enabled yet, so only IP endpoints are gossiped
/// (and legacy `addr` remains IP-only by construction).
#[must_use]
pub const fn addrv2_gossip_enabled(endpoint: PeerEndpoint) -> bool {
    matches!(endpoint, PeerEndpoint::Ip(_))
}

/// Core internal netgroup for an endpoint host (not the BIP155 tag).
///
/// IP uses the existing prefix/ASMap grouping via
/// [`crate::netgroup::NetGroups`] at call sites; overlay groups are
/// `[3, key[0]|0x0f]` / `[4, hash[0]|0x0f]` with `nBits = 4`.
#[must_use]
pub fn overlay_netgroup(host: EndpointHost) -> Option<Vec<u8>> {
    match host {
        EndpointHost::TorV3 { key } => Some(vec![3, key[0] | 0x0f]),
        EndpointHost::I2p { hash } => Some(vec![4, hash[0] | 0x0f]),
        EndpointHost::Ip(_) => None,
    }
}

/// Eviction netgroup for an unidentified (anonymous) session:
/// `vec![3] ++ SHA256(connection_id.to_le_bytes())[..2]`.
#[must_use]
pub fn anonymous_netgroup(connection_id: crate::ConnectionId) -> Vec<u8> {
    let digest = Sha256::digest(connection_id.get().to_le_bytes());
    vec![3, digest[0], digest[1]]
}

/// Routing configuration for dials. In this slice no overlay route is
/// configured, so Tor/I2P dials are typed unavailable; slice B fills the
/// SOCKS/SAM members without changing call sites.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialRoutes {
    /// Placeholder kept intentionally empty until slice B; overlays disabled.
    pub overlays_enabled: bool,
}

/// The single transport-match dial function.
///
/// `Ip` dials exactly as direct TCP did before. `TorV3`/`I2p` return a
/// typed transport-unavailable error: no SOCKS/SAM dial, no system DNS,
/// and never a direct-TCP fallback.
pub fn connect_peer_stream(
    endpoint: PeerEndpoint,
    _routes: &DialRoutes,
    timeout: Duration,
) -> io::Result<TcpStream> {
    match endpoint {
        PeerEndpoint::Ip(addr) => TcpStream::connect_timeout(&addr, timeout),
        PeerEndpoint::TorV3 { .. } | PeerEndpoint::I2p { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "overlay transport unavailable: Tor/I2P transports are not enabled",
        )),
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
    fn parse_format_round_trips() {
        for endpoint in [
            PeerEndpoint::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333)),
            PeerEndpoint::Ip("[::1]:8333".parse::<SocketAddr>().expect("v6")),
            tor_endpoint(),
            PeerEndpoint::I2p {
                hash: [5u8; 32],
                port: 7656,
            },
        ] {
            let text = format_endpoint(endpoint);
            assert_eq!(parse_endpoint(&text), Some(endpoint), "{text}");
        }
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
        // Short onion, uppercase, zero port, unknown suffix.
        assert_eq!(parse_endpoint("abc.onion:8333"), None);
        let good = format_endpoint(tor_endpoint());
        assert_eq!(parse_endpoint(&good.replace("8333", "0")), None);
        assert_eq!(parse_endpoint(&good.to_uppercase()), None);
        // I2P payload of wrong decoded length (51 chars is invalid length class).
        assert_eq!(
            parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(51))),
            None
        );
        assert_eq!(
            parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(53))),
            None
        );
        // Valid I2P: 52 chars of 'a' decode to 32 zero bytes.
        assert_eq!(
            parse_endpoint(&format!("{}.b32.i2p:8333", "a".repeat(52))),
            Some(PeerEndpoint::I2p {
                hash: [0u8; 32],
                port: 8333
            })
        );
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
            let error =
                connect_peer_stream(endpoint, &DialRoutes::default(), Duration::from_millis(10))
                    .expect_err("overlay must not dial");
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        }
    }

    #[test]
    fn overlay_netgroup_vectors() {
        assert_eq!(
            overlay_netgroup(EndpointHost::TorV3 { key: [0x21u8; 32] }),
            Some(vec![3, 0x2f])
        );
        assert_eq!(
            overlay_netgroup(EndpointHost::I2p { hash: [0x30u8; 32] }),
            Some(vec![4, 0x3f])
        );
        assert_eq!(
            overlay_netgroup(EndpointHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            None
        );
    }
}
