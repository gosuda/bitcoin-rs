//! Bounded, process-local avoidance of protocol-invalid remote IP addresses.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use hashbrown::{HashMap, HashSet};

/// Maximum exact IPs retained independently of the auxiliary address book.
pub const MAX_DISCOURAGED_IPS: usize = 4_096;
/// A single violation temporarily avoids automatic reconnection for one hour.
pub const DISCOURAGEMENT_LIFETIME: Duration = Duration::from_hours(1);

#[derive(Debug, Default)]
pub(crate) struct DiscouragedPeers {
    deadlines: HashMap<IpAddr, Instant>,
    oldest: VecDeque<IpAddr>,
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

    pub(crate) fn insert(&mut self, ip: IpAddr, now: Instant) {
        self.expire(now);
        let ip = ip.to_canonical();
        if self.deadlines.contains_key(&ip) {
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
        self.deadlines.insert(ip, until);
        self.oldest.push_back(ip);
    }

    pub(crate) fn contains(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.expire(now);
        self.deadlines.contains_key(&ip.to_canonical())
    }

    pub(crate) fn snapshot(&mut self, now: Instant) -> HashSet<IpAddr> {
        self.expire(now);
        self.deadlines.keys().copied().collect()
    }
}

/// Immutable policy captured before an address-book selection lock is acquired.
#[derive(Clone, Debug)]
pub struct AutomaticPeerPolicy {
    pub(crate) banned: Vec<crate::BannedSubnet>,
    pub(crate) discouraged: HashSet<IpAddr>,
    pub(crate) protected: std::sync::Arc<[crate::IpSubnet]>,
    pub(crate) now: SystemTime,
}

impl AutomaticPeerPolicy {
    /// Explicit operator bans take precedence over automatic protection.
    #[must_use]
    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        !crate::subnet::is_banned(&self.banned, ip, self.now)
            && (!self.discouraged.contains(&ip)
                || self.protected.iter().any(|subnet| subnet.contains(ip)))
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
        let first = IpAddr::from([8, 8, 8, 8]);
        entries.insert(first, now);
        entries.insert(first, now + Duration::from_secs(20));
        assert!(entries.contains(
            first,
            now + DISCOURAGEMENT_LIFETIME.saturating_sub(Duration::from_secs(1))
        ));
        assert!(!entries.contains(first, now + DISCOURAGEMENT_LIFETIME));
        for n in 0..=MAX_DISCOURAGED_IPS {
            let bytes = u32::try_from(n)?.to_be_bytes();
            entries.insert(IpAddr::from(bytes), now);
        }
        assert_eq!(entries.deadlines.len(), MAX_DISCOURAGED_IPS);
        assert_eq!(entries.oldest.len(), MAX_DISCOURAGED_IPS);
        assert!(!entries.contains(IpAddr::from([0, 0, 0, 0]), now));
        assert!(entries.snapshot(now + DISCOURAGEMENT_LIFETIME).is_empty());
        Ok(())
    }

    #[test]
    fn mapped_addresses_share_identity_and_local_exemptions()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let mut entries = DiscouragedPeers::default();
        entries.insert("::ffff:8.8.8.8".parse()?, now);
        assert!(entries.contains("8.8.8.8".parse()?, now));
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
