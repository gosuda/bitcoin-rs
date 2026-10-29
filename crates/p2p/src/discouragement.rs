//! Bounded, process-local avoidance of protocol-invalid remote peer addresses.

use bitcoin_rs_primitives::PeerAddress;
use std::collections::VecDeque;
use std::net::IpAddr;

use bitcoin_rs_primitives::{EndpointHost, PeerEndpoint};
use std::time::{Duration, Instant, SystemTime};

use hashbrown::{HashMap, HashSet};

/// Maximum exact peer addresses retained independently of the auxiliary address book.
pub const MAX_DISCOURAGED_IPS: usize = 4_096;
/// A single violation temporarily avoids automatic reconnection for one hour.
pub const DISCOURAGEMENT_LIFETIME: Duration = Duration::from_hours(1);

#[derive(Debug, Default)]
pub(crate) struct DiscouragedPeers {
    deadlines: HashMap<PeerAddress, Instant>,
    oldest: VecDeque<PeerAddress>,
}

impl DiscouragedPeers {
    fn expire(&mut self, now: Instant) {
        while self
            .oldest
            .front()
            .is_some_and(|ip| self.deadlines.get(ip).is_none_or(|until| *until <= now))
        {
            if let Some(ip) = self.oldest.pop_front() {
                self.deadlines.remove(&ip);
            }
        }
    }

    /// Record a reconnectable address and report whether it is retained.
    pub(crate) fn insert(&mut self, ip: impl Into<PeerAddress>, now: Instant) -> bool {
        self.expire(now);
        let ip = ip.into().to_canonical();
        if self.deadlines.contains_key(&ip) {
            return true;
        }
        let Some(until) = now.checked_add(DISCOURAGEMENT_LIFETIME) else {
            return false;
        };
        if self.deadlines.len() == MAX_DISCOURAGED_IPS
            && let Some(oldest) = self.oldest.pop_front()
        {
            self.deadlines.remove(&oldest);
        }
        self.deadlines.insert(ip, until);
        self.oldest.push_back(ip);
        true
    }

    pub(crate) fn contains(&mut self, ip: impl Into<PeerAddress>, now: Instant) -> bool {
        self.expire(now);
        self.deadlines.contains_key(&ip.into().to_canonical())
    }

    pub(crate) fn snapshot(&mut self, now: Instant) -> HashSet<PeerAddress> {
        self.expire(now);
        self.deadlines.keys().copied().collect()
    }
}

/// Immutable policy captured before an address-book selection lock is acquired.
#[derive(Clone, Debug)]
pub struct AutomaticPeerPolicy {
    pub(crate) banned: Vec<crate::BannedSubnet>,
    pub(crate) discouraged: HashSet<PeerAddress>,
    pub(crate) protected: std::sync::Arc<[crate::IpSubnet]>,
    pub(crate) now: SystemTime,
    pub(crate) routing: std::sync::Arc<crate::overlay::OverlayConfig>,
}

impl AutomaticPeerPolicy {
    /// Explicit operator bans take precedence over automatic protection.
    #[must_use]
    pub fn allows(&self, ip: impl Into<PeerAddress>) -> bool {
        let ip = ip.into().to_canonical();
        self.routing.allows(ip.network())
            && !ip
                .ip()
                .is_some_and(|ip| crate::subnet::is_banned(&self.banned, ip, self.now))
            && (!self.discouraged.contains(&ip)
                || ip
                    .ip()
                    .is_some_and(|ip| self.protected.iter().any(|subnet| subnet.contains(ip))))
    }

    /// Whether automatic dialing may use `endpoint`. Manual bans are
    /// IP-only; overlay hosts are discouraged by their port-free host.
    /// This is the routing-gate-free form used at the connection boundary,
    /// where `onlynet` was already enforced at dial time.
    #[must_use]
    pub fn allows_endpoint(&self, endpoint: PeerEndpoint) -> bool {
        match endpoint {
            PeerEndpoint::Ip(socket) => {
                let ip = crate::netgroup::canonical_ip(socket.ip());
                !crate::subnet::is_banned(&self.banned, ip, self.now)
                    && (!self
                        .discouraged
                        .contains(&PeerAddress::from(crate::EndpointHost::Ip(ip)))
                        || self.protected.iter().any(|subnet| subnet.contains(ip)))
            }
            PeerEndpoint::TorV3 { .. } | PeerEndpoint::I2p { .. } => {
                !self
                    .discouraged
                    .contains(&PeerAddress::from(endpoint.host()))
            }
        }
    }
}

/// Whether an endpoint is local; overlay endpoints are never local.
pub(crate) fn is_local_endpoint(endpoint: PeerEndpoint) -> bool {
    match endpoint {
        PeerEndpoint::Ip(socket) => is_local(socket.ip()),
        PeerEndpoint::TorV3 { .. } | PeerEndpoint::I2p { .. } => false,
    }
}

/// Core `CNetAddr::IsLocal`: IPv4 0/8, 127/8 and IPv6 loopback.
pub(crate) fn is_local(address: impl Into<PeerAddress>) -> bool {
    let Some(ip) = address.into().ip() else {
        return false;
    };
    match ip.to_canonical() {
        IpAddr::V4(ip) => matches!(ip.octets()[0], 0 | 127),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::PeerEndpoint;

    #[test]
    fn avoidance_is_bounded_expires_and_does_not_refresh_on_repetition()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let mut entries = DiscouragedPeers::default();
        let first = PeerAddress::Ip(IpAddr::from([8, 8, 8, 8]));
        entries.insert(first, now);
        entries.insert(first, now + Duration::from_secs(20));
        assert!(entries.contains(
            first,
            now + DISCOURAGEMENT_LIFETIME.saturating_sub(Duration::from_secs(1))
        ));
        assert!(!entries.contains(first, now + DISCOURAGEMENT_LIFETIME));
        for n in 0..=MAX_DISCOURAGED_IPS {
            let bytes = u32::try_from(n)?.to_be_bytes();
            entries.insert(PeerAddress::Ip(IpAddr::from(bytes)), now);
        }
        assert_eq!(entries.deadlines.len(), MAX_DISCOURAGED_IPS);
        assert_eq!(entries.oldest.len(), MAX_DISCOURAGED_IPS);
        assert!(!entries.contains(PeerAddress::Ip(IpAddr::from([0, 0, 0, 0])), now));
        assert!(entries.snapshot(now + DISCOURAGEMENT_LIFETIME).is_empty());
        Ok(())
    }

    #[test]
    fn overlay_hosts_are_discouraged_by_port_free_host() {
        let now = Instant::now();
        let mut entries = DiscouragedPeers::default();
        let tor = PeerEndpoint::TorV3 {
            key: [3u8; 32],
            port: 8333,
        };
        entries.insert(tor.address(), now);
        // Same key at any port shares the discouragement (port zeroed).
        assert!(entries.contains(tor.with_port(9999).address(), now));
        assert!(
            entries.contains(
                PeerEndpoint::TorV3 {
                    key: [3u8; 32],
                    port: 1
                }
                .address(),
                now
            )
        );
        assert!(
            !entries.contains(
                PeerEndpoint::TorV3 {
                    key: [4u8; 32],
                    port: 8333
                }
                .address(),
                now
            )
        );
        assert!(!is_local(tor.address()));
        // Snapshot keys carry no port and no socket.
        assert!(
            entries
                .snapshot(now)
                .iter()
                .all(|host| matches!(host, PeerAddress::Onion(_)))
        );
    }

    #[test]
    fn mapped_addresses_share_identity_and_local_exemptions()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let mut entries = DiscouragedPeers::default();
        entries.insert("::ffff:8.8.8.8".parse::<std::net::IpAddr>()?, now);
        assert!(entries.contains("8.8.8.8".parse::<std::net::IpAddr>()?, now));
        for ip in [
            "127.0.0.1",
            "127.4.3.2",
            "0.1.2.3",
            "::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_local(ip.parse::<IpAddr>()?));
        }
        for ip in ["8.8.8.8", "10.1.2.3", "::", "2001:4860::1"] {
            assert!(!is_local(ip.parse::<IpAddr>()?));
        }
        Ok(())
    }
}
