//! Typed logical peer endpoint identity, independent of any socket.
//!
//! A `PeerEndpoint` identifies the logical peer. A socket address is only
//! the identity for direct-IP peers; Tor v3 and I2P peers are identified by
//! their overlay keys/hashes and never by a proxy's loopback socket.

use core::fmt;
use std::net::{IpAddr, SocketAddr};

use sha3::{Digest, Sha3_256};

/// Logical identity of one peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerEndpoint {
    /// Direct-IP peer, identified by its socket address.
    Ip(SocketAddr),
    /// Tor v3 peer, identified by its 32-byte Ed25519 public key.
    TorV3 {
        /// Ed25519 public key from the v3 onion address.
        key: [u8; 32],
        /// Service port.
        port: u16,
    },
    /// I2P peer, identified by the 32-byte hash of its destination.
    I2p {
        /// SHA-256 hash of the I2P destination.
        hash: [u8; 32],
        /// Service port.
        port: u16,
    },
}

/// Port-free host part of a [`PeerEndpoint`]; discouragement keys use this
/// with the port zeroed/discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointHost {
    /// Direct-IP host.
    Ip(IpAddr),
    /// Tor v3 host key.
    TorV3 {
        /// Ed25519 public key.
        key: [u8; 32],
    },
    /// I2P host hash.
    I2p {
        /// Destination hash.
        hash: [u8; 32],
    },
}

/// Network classification of an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkLabel {
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
    /// Tor onion.
    Onion,
    /// I2P.
    I2p,
}

impl NetworkLabel {
    /// Core `getnetworkinfo` / `getpeerinfo` spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Onion => "onion",
            Self::I2p => "i2p",
        }
    }
}

impl fmt::Display for NetworkLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PeerEndpoint {
    /// BIP155 network id: 1 `IPv4`, 2 `IPv6`, 4 `TorV3`, 5 `I2P`.
    #[must_use]
    pub const fn network_id(self) -> u8 {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(_) => 1,
                SocketAddr::V6(_) => 2,
            },
            Self::TorV3 { .. } => 4,
            Self::I2p { .. } => 5,
        }
    }

    /// Service port.
    #[must_use]
    pub const fn port(self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::TorV3 { port, .. } | Self::I2p { port, .. } => port,
        }
    }

    /// Port-free host identity.
    #[must_use]
    pub fn host(self) -> EndpointHost {
        match self {
            Self::Ip(addr) => EndpointHost::Ip(addr.ip()),
            Self::TorV3 { key, .. } => EndpointHost::TorV3 { key },
            Self::I2p { hash, .. } => EndpointHost::I2p { hash },
        }
    }

    /// Network classification.
    #[must_use]
    pub const fn net(self) -> NetworkLabel {
        match self {
            Self::Ip(SocketAddr::V4(_)) => NetworkLabel::Ipv4,
            Self::Ip(SocketAddr::V6(_)) => NetworkLabel::Ipv6,
            Self::TorV3 { .. } => NetworkLabel::Onion,
            Self::I2p { .. } => NetworkLabel::I2p,
        }
    }

    /// Direct-IP socket, when this is an IP endpoint.
    #[must_use]
    pub const fn as_ip(self) -> Option<SocketAddr> {
        match self {
            Self::Ip(addr) => Some(addr),
            _ => None,
        }
    }

    /// This endpoint with its port replaced by `port`.
    #[must_use]
    pub fn with_port(self, port: u16) -> Self {
        match self {
            Self::Ip(addr) => Self::Ip(SocketAddr::new(addr.ip(), port)),
            Self::TorV3 { key, .. } => Self::TorV3 { key, port },
            Self::I2p { hash, .. } => Self::I2p { hash, port },
        }
    }

    /// Full 56-character Tor v3 onion hostname (without `.onion` suffix
    /// handling beyond the hostname itself is the caller's formatting).
    #[must_use]
    pub fn tor_onion_hostname(key: &[u8; 32]) -> String {
        base32_encode(&tor_v3_payload(key))
    }

    /// Full 52-character I2P base32 hostname for `hash`.
    #[must_use]
    pub fn i2p_b32_hostname(hash: &[u8; 32]) -> String {
        base32_encode(hash)
    }
}

impl EndpointHost {
    /// Reattach a port to form an endpoint.
    #[must_use]
    pub fn endpoint(self, port: u16) -> PeerEndpoint {
        match self {
            Self::Ip(ip) => PeerEndpoint::Ip(SocketAddr::new(ip, port)),
            Self::TorV3 { key } => PeerEndpoint::TorV3 { key, port },
            Self::I2p { hash } => PeerEndpoint::I2p { hash, port },
        }
    }

    /// Network classification.
    #[must_use]
    pub const fn net(self) -> NetworkLabel {
        match self {
            Self::Ip(IpAddr::V4(_)) => NetworkLabel::Ipv4,
            Self::Ip(IpAddr::V6(_)) => NetworkLabel::Ipv6,
            Self::TorV3 { .. } => NetworkLabel::Onion,
            Self::I2p { .. } => NetworkLabel::I2p,
        }
    }

    /// BIP155 network id of the host family.
    #[must_use]
    pub const fn network_id(self) -> u8 {
        match self {
            Self::Ip(IpAddr::V4(_)) => 1,
            Self::Ip(IpAddr::V6(_)) => 2,
            Self::TorV3 { .. } => 4,
            Self::I2p { .. } => 5,
        }
    }
}

impl fmt::Display for EndpointHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::TorV3 { key } => write!(f, "{}.onion", PeerEndpoint::tor_onion_hostname(key)),
            Self::I2p { hash } => write!(f, "{}.b32.i2p", PeerEndpoint::i2p_b32_hostname(hash)),
        }
    }
}

impl From<std::net::SocketAddr> for PeerEndpoint {
    fn from(socket: std::net::SocketAddr) -> Self {
        Self::Ip(socket)
    }
}

impl fmt::Display for PeerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::TorV3 { port, .. } | Self::I2p { port, .. } => {
                write!(f, "{}:{port}", self.host())
            }
        }
    }
}

/// 35-byte Tor v3 payload: key || checksum(2) || version(0x03).
#[must_use]
pub fn tor_v3_payload(key: &[u8; 32]) -> [u8; 35] {
    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(key);
    payload[34] = 0x03;
    let checksum = tor_v3_checksum(key);
    payload[32] = checksum[0];
    payload[33] = checksum[1];
    payload
}

/// Tor v3 checksum: first two bytes of
/// SHA3-256(".onion checksum" || key || version).
#[must_use]
pub fn tor_v3_checksum(key: &[u8; 32]) -> [u8; 2] {
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(key);
    hasher.update([0x03u8]);
    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

/// Validate a decoded 35-byte Tor v3 payload; returns the key on success.
#[must_use]
pub fn tor_v3_key_from_payload(payload: &[u8]) -> Option<[u8; 32]> {
    if payload.len() != 35 || payload[34] != 0x03 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&payload[..32]);
    let expected = tor_v3_checksum(&key);
    if payload[32] != expected[0] || payload[33] != expected[1] {
        return None;
    }
    Some(key)
}

const B32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lowercase, no padding (onion / I2P b32 form).
#[must_use]
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = usize::try_from((buffer >> bits) & 0x1f).unwrap_or(0);
            out.push(char::from(B32_ALPHABET[idx]));
        }
        // Keep only the not-yet-emitted low `bits`.
        buffer &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        let idx = usize::try_from((buffer << (5 - bits)) & 0x1f).unwrap_or(0);
        out.push(char::from(B32_ALPHABET[idx]));
    }
    out
}

/// Decode RFC 4648 lowercase base32 without padding. Rejects uppercase,
/// padding, non-alphabet bytes, non-zero trailing pad bits, and lengths
/// that cannot encode whole bytes.
#[must_use]
pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    // Valid unpadded lengths mod 8 are 0,2,4,5,7 (whole-byte encodings).
    if !matches!(text.len() % 8, 0 | 2 | 4 | 5 | 7) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).unwrap_or(0));
        }
        buffer &= (1u32 << bits) - 1;
    }
    if bits > 0 && buffer != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn endpoint_accessors() {
        let v4 = PeerEndpoint::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333));
        assert_eq!(v4.network_id(), 1);
        assert_eq!(v4.net(), NetworkLabel::Ipv4);
        assert_eq!(v4.port(), 8333);
        assert_eq!(v4.host(), EndpointHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let v6 = PeerEndpoint::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8333));
        assert_eq!(v6.network_id(), 2);
        assert_eq!(v6.net(), NetworkLabel::Ipv6);
        let tor = PeerEndpoint::TorV3 {
            key: [7u8; 32],
            port: 8333,
        };
        assert_eq!(tor.network_id(), 4);
        assert_eq!(tor.net(), NetworkLabel::Onion);
        assert_eq!(
            tor.host().endpoint(9999),
            PeerEndpoint::TorV3 {
                key: [7u8; 32],
                port: 9999
            }
        );
        let i2p = PeerEndpoint::I2p {
            hash: [9u8; 32],
            port: 7656,
        };
        assert_eq!(i2p.network_id(), 5);
        assert_eq!(i2p.net(), NetworkLabel::I2p);
    }

    #[test]
    fn tor_payload_checksum_round_trip() {
        // Known Tor v3 test vector key (all-zero key payload is deterministic).
        let key = [0u8; 32];
        let payload = tor_v3_payload(&key);
        assert_eq!(payload[34], 0x03);
        assert_eq!(tor_v3_key_from_payload(&payload), Some(key));
        let mut bad = payload;
        bad[32] ^= 0xff;
        assert_eq!(tor_v3_key_from_payload(&bad), None);
        let mut bad_version = payload;
        bad_version[34] = 0x04;
        // Fixing checksum for wrong version still fails version gate.
        assert_eq!(tor_v3_key_from_payload(&bad_version), None);
        assert_eq!(tor_v3_key_from_payload(&payload[..34]), None);
        let host = PeerEndpoint::tor_onion_hostname(&key);
        assert_eq!(host.len(), 56);
        assert_eq!(base32_decode(&host).as_deref(), Some(&payload[..]));
    }

    #[test]
    fn base32_rejects_invalid() {
        assert_eq!(base32_decode("ABC"), None); // uppercase
        assert_eq!(base32_decode("ab="), None); // padding / bad char
        assert_eq!(base32_decode("a"), None); // impossible length
        assert_eq!(base32_decode("aa").map(|v| v.len()), Some(1));
        assert_eq!(base32_decode("ab"), None);
        assert_eq!(base32_decode("ac"), None);
    }
}
