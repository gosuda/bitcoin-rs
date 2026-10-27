//! Logical Bitcoin peer destinations, independent of the socket carrying them.
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};

/// Network used by a logical peer destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerNetwork {
    /// IPv4 TCP.
    Ipv4,
    /// IPv6 TCP.
    Ipv6,
    /// Tor v3.
    Onion,
    /// I2P streaming.
    I2p,
}

impl PeerNetwork {
    /// RPC/configuration spelling.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Onion => "onion",
            Self::I2p => "i2p",
        }
    }
}

/// Routable Bitcoin peer address, independent of a live connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PeerAddress {
    /// Ordinary IP address.
    Ip(IpAddr),
    /// Tor v3 service public key.
    Onion([u8; 32]),
    /// SHA256 of an I2P public Destination.
    I2p([u8; 32]),
}

impl PeerAddress {
    /// Canonicalize mapped IPs without changing overlay identities.
    #[must_use]
    pub fn to_canonical(self) -> Self {
        match self {
            Self::Ip(ip) => Self::Ip(ip.to_canonical()),
            other => other,
        }
    }
    /// IP when this is an IP identity.
    pub const fn ip(self) -> Option<IpAddr> {
        if let Self::Ip(ip) = self {
            Some(ip)
        } else {
            None
        }
    }
    /// Transport network.
    pub const fn network(self) -> PeerNetwork {
        match self {
            Self::Ip(IpAddr::V4(_)) => PeerNetwork::Ipv4,
            Self::Ip(IpAddr::V6(ip)) => {
                if ip.to_ipv4_mapped().is_some() {
                    PeerNetwork::Ipv4
                } else {
                    PeerNetwork::Ipv6
                }
            }
            Self::Onion(_) => PeerNetwork::Onion,
            Self::I2p(_) => PeerNetwork::I2p,
        }
    }
    /// Whether an IP identity is loopback. Overlay identities never inherit proxy exemptions.
    pub fn is_loopback(self) -> bool {
        self.ip().is_some_and(|ip| ip.is_loopback())
    }
    /// Whether an IP identity is unspecified.
    pub fn is_unspecified(self) -> bool {
        self.ip().is_some_and(|ip| ip.is_unspecified())
    }
    /// Whether an IP identity is multicast.
    pub fn is_multicast(self) -> bool {
        self.ip().is_some_and(|ip| ip.is_multicast())
    }
}
impl From<IpAddr> for PeerAddress {
    fn from(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }
}

/// Bitcoin service endpoint. Local proxy/router sockets are stored separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PeerEndpoint {
    address: PeerAddress,
    port: u16,
    flowinfo: u32,
    scope_id: u32,
}
impl PeerEndpoint {
    /// Construct an endpoint from its logical identity and port.
    pub fn new(address: impl Into<PeerAddress>, port: u16) -> Self {
        Self {
            address: address.into(),
            port,
            flowinfo: 0,
            scope_id: 0,
        }
    }
    /// Logical remote identity, without port.
    pub const fn address(self) -> PeerAddress {
        self.address
    }
    /// Service port.
    pub const fn port(self) -> u16 {
        self.port
    }
    /// Direct TCP address, only for IP destinations.
    pub fn socket_addr(self) -> Option<SocketAddr> {
        self.address.ip().map(|ip| match ip {
            IpAddr::V4(ip) => SocketAddr::new(ip.into(), self.port),
            IpAddr::V6(ip) => SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                self.port,
                self.flowinfo,
                self.scope_id,
            )),
        })
    }
    /// Canonical IP identity with native IPv6 socket scope retained.
    #[must_use]
    pub fn to_canonical(self) -> Self {
        if self.address.to_canonical() == self.address {
            self
        } else {
            Self::new(self.address.to_canonical(), self.port)
        }
    }
    /// Whether this is an IPv4 destination.
    pub const fn is_ipv4(&self) -> bool {
        matches!(self.address, PeerAddress::Ip(IpAddr::V4(_)))
    }
    /// Whether this is an IPv6 destination.
    pub const fn is_ipv6(&self) -> bool {
        matches!(self.address, PeerAddress::Ip(IpAddr::V6(_)))
    }
}
impl From<SocketAddr> for PeerEndpoint {
    fn from(addr: SocketAddr) -> Self {
        let mut endpoint = Self::new(addr.ip(), addr.port());
        if let SocketAddr::V6(addr) = addr {
            endpoint.flowinfo = addr.flowinfo();
            endpoint.scope_id = addr.scope_id();
        }
        endpoint
    }
}
impl<T> From<(T, u16)> for PeerEndpoint
where
    SocketAddr: From<(T, u16)>,
{
    fn from(value: (T, u16)) -> Self {
        Self::from(SocketAddr::from(value))
    }
}

/// Lowercase RFC4648 base32 without padding, shared by overlay address encodings.
pub fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = String::new();
    let mut bits = 0_u32;
    let mut count = 0;
    for &byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        count += 8;
        while count >= 5 {
            count -= 5;
            output.push(char::from(
                ALPHABET[usize::try_from((bits >> count) & 31).unwrap_or_default()],
            ));
        }
    }
    if count > 0 {
        output.push(char::from(
            ALPHABET[usize::try_from((bits << (5 - count)) & 31).unwrap_or_default()],
        ));
    }
    output
}
fn base32_decode<const N: usize>(text: &str) -> Result<[u8; N], &'static str> {
    let mut output = [0; N];
    let mut index = 0;
    let mut bits = 0_u32;
    let mut count = 0;
    for ch in text.bytes() {
        let value = match ch {
            b'a'..=b'z' => ch - b'a',
            b'2'..=b'7' => ch - b'2' + 26,
            _ => return Err("invalid base32 destination"),
        };
        bits = (bits << 5) | u32::from(value);
        count += 5;
        if count >= 8 {
            count -= 8;
            *output.get_mut(index).ok_or("oversized destination")? =
                u8::try_from((bits >> count) & 255).unwrap_or_default();
            index += 1;
        }
    }
    if index != N || bits & ((1 << count) - 1) != 0 {
        return Err("invalid destination length or padding");
    }
    Ok(output)
}
fn onion_bytes(key: &[u8; 32]) -> [u8; 35] {
    let mut bytes = [0; 35];
    bytes[..32].copy_from_slice(key);
    bytes[34] = 3;
    let mut digest = Sha3_256::new();
    digest.update(b".onion checksum");
    digest.update(key);
    digest.update([3]);
    bytes[32..34].copy_from_slice(&digest.finalize()[..2]);
    bytes
}
impl fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Onion(key) => write!(f, "{}.onion", base32_encode(&onion_bytes(key))),
            Self::I2p(hash) => write!(f, "{}.b32.i2p", base32_encode(hash)),
        }
    }
}
impl fmt::Display for PeerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(addr) = self.socket_addr() {
            addr.fmt(f)
        } else {
            write!(f, "{}:{}", self.address, self.port)
        }
    }
}
impl FromStr for PeerAddress {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        let text = value.to_ascii_lowercase();
        if let Some(name) = text.strip_suffix(".onion") {
            if name.len() != 56 {
                return Err("only Tor v3 destinations are supported");
            }
            let bytes = base32_decode::<35>(name)?;
            let mut key = [0; 32];
            key.copy_from_slice(&bytes[..32]);
            if bytes != onion_bytes(&key) {
                return Err("invalid Tor v3 checksum or version");
            }
            return Ok(Self::Onion(key));
        }
        if let Some(name) = text.strip_suffix(".b32.i2p") {
            if name.len() != 52 {
                return Err("invalid I2P base32 destination length");
            }
            return Ok(Self::I2p(base32_decode(name)?));
        }
        Err("expected IP, Tor v3, or I2P base32 destination")
    }
}
impl FromStr for PeerEndpoint {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(socket) = value.parse::<SocketAddr>() {
            return Ok(Self::from(socket));
        }
        let (host, port) = value
            .rsplit_once(':')
            .ok_or("destination requires a port")?;
        if host.contains(':') {
            return Err("IPv6 endpoints require brackets");
        }
        Ok(Self::new(
            host.parse::<PeerAddress>()?,
            port.parse().map_err(|_| "invalid destination port")?,
        ))
    }
}
impl Serialize for PeerEndpoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for PeerEndpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let endpoint: Self = String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)?;
        Ok(endpoint)
    }
}
impl Serialize for PeerAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for PeerAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let address: Self = String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)?;
        Ok(address)
    }
}

impl FromStr for PeerNetwork {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            "onion" => Ok(Self::Onion),
            "i2p" => Ok(Self::I2p),
            _ => Err("expected ipv4, ipv6, onion, or i2p"),
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
