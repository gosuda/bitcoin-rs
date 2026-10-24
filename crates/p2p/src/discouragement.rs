//! Bounded, process-local avoidance of protocol-invalid remote IP addresses.

use std::collections::VecDeque;
use std::net::IpAddr;

use bitcoin_rs_primitives::{EndpointHost, PeerEndpoint};
use std::time::{Duration, Instant, SystemTime};

use hashbrown::{HashMap, HashSet};

/// Maximum exact IPs retained independently of the auxiliary address book.
pub const MAX_DISCOURAGED_IPS: usize = 4_096;
/// A single violation temporarily avoids automatic reconnection for one hour.
pub const DISCOURAGEMENT_LIFETIME: Duration = Duration::from_hours(1);

#[derive(Debug, Default)]
pub(crate) struct DiscouragedPeers {
    deadlines: HashMap<EndpointHost, Instant>,
    oldest: VecDeque<EndpointHost>,
}

fn canonical_host(host: EndpointHost) -> EndpointHost {
    match host {
        EndpointHost::Ip(ip) => EndpointHost::Ip(crate::netgroup::canonical_ip(ip)),
        overlay => overlay,
    }
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

    pub(crate) fn insert(&mut self, host: EndpointHost, now: Instant) {
        self.expire(now);
        let host = canonical_host(host);
        if self.deadlines.contains_key(&host) {
            return;
        }
        let Some(until) = now.checked_add(DISCOURAGEMENT_LIFETIME) else {
            return;
        };
        if self.deadlines.len() == MAX_DISCOURAGED_IPS
            && let Some(oldest) = self.oldest.pop_front()
        {
            self.deadlines.remove(&oldest);
        }
        self.deadlines.insert(host, until);
        self.oldest.push_back(host);
    }

    pub(crate) fn contains(&mut self, host: EndpointHost, now: Instant) -> bool {
        self.expire(now);
        self.deadlines.contains_key(&canonical_host(host))
    }

    pub(crate) fn snapshot(&mut self, now: Instant) -> HashSet<EndpointHost> {
        self.expire(now);
        self.deadlines.keys().copied().collect()
    }
}

/// Immutable policy captured before an address-book selection lock is acquired.
#[derive(Clone, Debug)]
pub struct AutomaticPeerPolicy {
    pub(crate) banned: Vec<crate::BannedSubnet>,
    pub(crate) discouraged: HashSet<EndpointHost>,
    pub(crate) protected: std::sync::Arc<[crate::IpSubnet]>,
    pub(crate) now: SystemTime,
}

impl AutomaticPeerPolicy {
    /// Explicit operator bans take precedence over automatic protection.
    #[must_use]
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.allows_endpoint(PeerEndpoint::Ip(std::net::SocketAddr::new(ip, 0)))
    }

    /// Whether automatic dialing may use `endpoint`. Manual bans are
    /// IP-only; overlay hosts are discouraged by their port-free host.
    #[must_use]
    pub fn allows_endpoint(&self, endpoint: PeerEndpoint) -> bool {
        match endpoint {
            PeerEndpoint::Ip(socket) => {
                let ip = crate::netgroup::canonical_ip(socket.ip());
                !crate::subnet::is_banned(&self.banned, ip, self.now)
                    && (!self.discouraged.contains(&EndpointHost::Ip(ip))
                        || self.protected.iter().any(|subnet| subnet.contains(ip)))
            }
            PeerEndpoint::TorV3 { .. } | PeerEndpoint::I2p { .. } => {
                !self.discouraged.contains(&endpoint.host())
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
pub(crate) fn is_local(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => matches!(ip.octets()[0], 0 | 127),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avoidance_is_bounded_expires_and_does_not_refresh_on_repetition()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let mut entries = DiscouragedPeers::default();
        let first = EndpointHost::Ip(IpAddr::from([8, 8, 8, 8]));
        entries.insert(first, now);
        entries.insert(first, now + Duration::from_secs(20));
        assert!(entries.contains(
            first,
            now + DISCOURAGEMENT_LIFETIME.saturating_sub(Duration::from_secs(1))
        ));
        assert!(!entries.contains(first, now + DISCOURAGEMENT_LIFETIME));
        for n in 0..=MAX_DISCOURAGED_IPS {
            let bytes = u32::try_from(n)?.to_be_bytes();
            entries.insert(EndpointHost::Ip(IpAddr::from(bytes)), now);
        }
        assert_eq!(entries.deadlines.len(), MAX_DISCOURAGED_IPS);
        assert_eq!(entries.oldest.len(), MAX_DISCOURAGED_IPS);
        assert!(!entries.contains(EndpointHost::Ip(IpAddr::from([0, 0, 0, 0])), now));
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
        entries.insert(tor.host(), now);
        // Same key at any port shares the discouragement (port zeroed).
        assert!(entries.contains(tor.with_port(9999).host(), now));
        assert!(
            entries.contains(
                PeerEndpoint::TorV3 {
                    key: [3u8; 32],
                    port: 1
                }
                .host(),
                now
            )
        );
        assert!(
            !entries.contains(
                PeerEndpoint::TorV3 {
                    key: [4u8; 32],
                    port: 8333
                }
                .host(),
                now
            )
        );
        assert!(!is_local_endpoint(tor));
        // Snapshot keys carry no port and no socket.
        assert!(
            entries
                .snapshot(now)
                .iter()
                .all(|host| matches!(host, EndpointHost::TorV3 { .. }))
        );
    }

    #[test]
    fn mapped_addresses_share_identity_and_local_exemptions()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let mut entries = DiscouragedPeers::default();
        entries.insert(EndpointHost::Ip("::ffff:8.8.8.8".parse()?), now);
        assert!(entries.contains(EndpointHost::Ip("8.8.8.8".parse()?), now));
        for ip in [
            "127.0.0.1",
            "127.4.3.2",
            "0.1.2.3",
            "::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_local(ip.parse()?));
        }
        for ip in ["8.8.8.8", "10.1.2.3", "::", "2001:4860::1"] {
            assert!(!is_local(ip.parse()?));
        }
        Ok(())
    }
}
