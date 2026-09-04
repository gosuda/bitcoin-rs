//! Live peer-session table: the single owner of connection leases and the
//! handshake metadata published for them.
//!
//! One connection per remote address is live at a time. Registration replaces
//! and cancels any predecessor at the same address; every removal path checks
//! connection identity so a stale handle can never evict its successor. All
//! consumers (listener, connection threads, block sync, RPC) observe and
//! mutate peer sessions only through this type, so the registration,
//! replacement, and cancellation rules have exactly one implementation.

use std::net::SocketAddr;

use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::connection::{ConnectionId, PeerLease, PeerSource};
use crate::peer_info::PeerInfo;

/// One live connection joined with its handshake metadata.
#[derive(Clone, Debug)]
pub struct PeerSession {
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Control handle for the connection.
    pub lease: PeerLease,
    /// Handshake metadata, `None` while the handshake is still in progress.
    pub info: Option<PeerInfo>,
}

#[derive(Debug)]
struct Entry {
    lease: PeerLease,
    info: Option<PeerInfo>,
}

/// Authoritative table of live peer connections keyed by remote address.
#[derive(Debug, Default)]
pub struct PeerTable {
    entries: RwLock<HashMap<SocketAddr, Entry>>,
}

impl PeerTable {
    /// Creates an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `lease` as the live connection at `addr`, cancelling and
    /// replacing any predecessor. Returns whether a different connection was
    /// replaced; re-registering the same connection is a no-op that keeps its
    /// published metadata.
    pub fn register(&self, addr: SocketAddr, lease: PeerLease) -> bool {
        let mut entries = self.entries.write();
        match entries.get(&addr) {
            Some(current) if current.lease.same_connection(&lease) => false,
            Some(_) => {
                let prior = entries.insert(addr, Entry { lease, info: None });
                if let Some(prior) = prior {
                    prior.lease.cancel();
                }
                true
            }
            None => {
                entries.insert(addr, Entry { lease, info: None });
                false
            }
        }
    }

    /// Publishes handshake metadata for the connection `lease` refers to.
    /// Returns `false` (and publishes nothing) when that connection is no
    /// longer the live one at `addr`.
    pub fn publish_info(&self, addr: SocketAddr, lease: &PeerLease, info: PeerInfo) -> bool {
        let mut entries = self.entries.write();
        match entries.get_mut(&addr) {
            Some(entry) if entry.lease.same_connection(lease) => {
                entry.info = Some(info);
                true
            }
            _ => false,
        }
    }

    /// Removes and cancels the connection `lease` refers to. Returns `false`
    /// when a different connection is live at `addr`, leaving it untouched.
    pub fn remove_current(&self, addr: SocketAddr, lease: &PeerLease) -> bool {
        self.remove_if(addr, |current| current.same_connection(lease))
    }

    /// Removes and cancels the connection that stamped `source`. Returns
    /// `false` when that connection is no longer live.
    pub fn disconnect_source(&self, source: PeerSource) -> bool {
        self.remove_if(source.addr, |current| current.is_current(source))
    }

    /// Removes and cancels whichever connection is live at `addr`.
    pub fn disconnect(&self, addr: SocketAddr) -> bool {
        self.remove_if(addr, |_| true)
    }

    /// Removes and cancels the live connection at `addr` only when its identity is `id`.
    pub fn disconnect_connection(&self, addr: SocketAddr, id: ConnectionId) -> bool {
        self.remove_if(addr, |current| current.connection_id() == id)
    }

    fn remove_if(&self, addr: SocketAddr, matches: impl FnOnce(&PeerLease) -> bool) -> bool {
        let mut entries = self.entries.write();
        if !entries
            .get(&addr)
            .is_some_and(|entry| matches(&entry.lease))
        {
            return false;
        }
        if let Some(removed) = entries.remove(&addr) {
            removed.lease.cancel();
        }
        true
    }

    /// Removes and cancels every connection accepted by `predicate`, returning
    /// the affected addresses.
    pub fn disconnect_matching(
        &self,
        predicate: impl Fn(&SocketAddr, &PeerLease) -> bool,
    ) -> Vec<SocketAddr> {
        let mut entries = self.entries.write();
        let targets: Vec<SocketAddr> = entries
            .iter()
            .filter(|(addr, entry)| predicate(addr, &entry.lease))
            .map(|(addr, _)| *addr)
            .collect();
        for addr in &targets {
            if let Some(removed) = entries.remove(addr) {
                removed.lease.cancel();
            }
        }
        targets
    }

    /// Requests teardown of every live connection without removing its entry.
    /// Connection owners remove their own session after observing the
    /// cancellation, so identity checks on the way out still succeed.
    pub fn cancel_all(&self) {
        for entry in self.entries.read().values() {
            entry.lease.cancel();
        }
    }

    /// Returns whether any connection is live at `addr`.
    #[must_use]
    pub fn is_connected(&self, addr: SocketAddr) -> bool {
        self.entries.read().contains_key(&addr)
    }

    /// Returns whether the connection that stamped `source` is still live.
    #[must_use]
    pub fn is_current(&self, source: PeerSource) -> bool {
        self.entries
            .read()
            .get(&source.addr)
            .is_some_and(|entry| entry.lease.is_current(source))
    }

    /// Clones the lease of the live connection at `addr`.
    #[must_use]
    pub fn lease(&self, addr: SocketAddr) -> Option<PeerLease> {
        self.entries
            .read()
            .get(&addr)
            .map(|entry| entry.lease.clone())
    }

    /// Number of live connections, including those still handshaking.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns whether no connection is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Addresses of every live connection.
    #[must_use]
    pub fn addrs(&self) -> Vec<SocketAddr> {
        self.entries.read().keys().copied().collect()
    }

    /// Address and connection identity of every live connection.
    #[must_use]
    pub fn live_connections(&self) -> Vec<(SocketAddr, ConnectionId)> {
        self.entries
            .read()
            .iter()
            .map(|(addr, entry)| (*addr, entry.lease.connection_id()))
            .collect()
    }

    /// Calls `f` with every live lease under the table's read lock.
    pub fn for_each_lease(&self, mut f: impl FnMut(SocketAddr, &PeerLease)) {
        for (addr, entry) in self.entries.read().iter() {
            f(*addr, &entry.lease);
        }
    }

    /// Metadata of every handshake-complete connection, ordered by connection
    /// identity (connection order).
    #[must_use]
    pub fn infos(&self) -> Vec<PeerInfo> {
        let entries = self.entries.read();
        let mut infos: Vec<(ConnectionId, &PeerInfo)> = entries
            .values()
            .filter_map(|entry| {
                entry
                    .info
                    .as_ref()
                    .map(|info| (entry.lease.connection_id(), info))
            })
            .collect();
        infos.sort_unstable_by_key(|(id, _)| id.get());
        infos.into_iter().map(|(_, info)| info.clone()).collect()
    }

    /// Snapshot of every live connection, ordered by connection identity.
    #[must_use]
    pub fn sessions(&self) -> Vec<PeerSession> {
        let entries = self.entries.read();
        let mut sessions: Vec<PeerSession> = entries
            .iter()
            .map(|(addr, entry)| PeerSession {
                addr: *addr,
                lease: entry.lease.clone(),
                info: entry.info.clone(),
            })
            .collect();
        sessions.sort_unstable_by_key(|session| session.lease.connection_id().get());
        sessions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn lease() -> PeerLease {
        let (tx, _rx) = crossbeam_channel::unbounded();
        PeerLease::new(tx)
    }

    fn info(addr: SocketAddr, start_height: i32) -> PeerInfo {
        PeerInfo {
            addr,
            version: 70016,
            services: 0,
            user_agent: String::new(),
            start_height,
            conn_time: 0,
            inbound: false,
        }
    }

    #[test]
    fn register_replaces_and_cancels_predecessor_only() {
        let table = PeerTable::new();
        let first = lease();
        let second = lease();
        assert!(!table.register(addr(1), first.clone()));
        assert!(table.register(addr(1), second.clone()));
        assert!(first.is_cancelled());
        assert!(!second.is_cancelled());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn re_registering_current_connection_is_noop_and_keeps_info() {
        let table = PeerTable::new();
        let current = lease();
        table.register(addr(1), current.clone());
        assert!(table.publish_info(addr(1), &current, info(addr(1), 7)));
        assert!(!table.register(addr(1), current.clone()));
        assert!(!current.is_cancelled());
        assert_eq!(table.infos().len(), 1);
    }

    #[test]
    fn publish_info_rejects_stale_connection() {
        let table = PeerTable::new();
        let stale = lease();
        let current = lease();
        table.register(addr(1), stale.clone());
        table.register(addr(1), current.clone());
        assert!(!table.publish_info(addr(1), &stale, info(addr(1), 1)));
        assert!(table.infos().is_empty());
        assert!(table.publish_info(addr(1), &current, info(addr(1), 2)));
        assert_eq!(table.infos()[0].start_height, 2);
    }

    #[test]
    fn stale_handle_cannot_remove_successor() {
        let table = PeerTable::new();
        let stale = lease();
        let current = lease();
        table.register(addr(1), stale.clone());
        table.register(addr(1), current.clone());
        assert!(!table.remove_current(addr(1), &stale));
        assert!(!table.disconnect_source(stale.source(addr(1))));
        assert!(table.is_connected(addr(1)));
        assert!(!current.is_cancelled());
        assert!(table.disconnect_source(current.source(addr(1))));
        assert!(current.is_cancelled());
        assert!(table.is_empty());
    }

    #[test]
    fn disconnect_removes_lease_and_info_together() {
        let table = PeerTable::new();
        let current = lease();
        table.register(addr(1), current.clone());
        table.publish_info(addr(1), &current, info(addr(1), 1));
        assert!(table.disconnect(addr(1)));
        assert!(!table.disconnect(addr(1)));
        assert!(current.is_cancelled());
        assert!(table.infos().is_empty());
        assert!(table.lease(addr(1)).is_none());
    }

    #[test]
    fn disconnect_connection_does_not_remove_replacement() {
        let table = PeerTable::new();
        let stale = lease();
        let replacement = lease();
        table.register(addr(1), stale.clone());
        let stale_id = stale.connection_id();
        table.register(addr(1), replacement.clone());
        assert!(!table.disconnect_connection(addr(1), stale_id));
        assert!(table.is_connected(addr(1)));
        assert!(!replacement.is_cancelled());
    }

    #[test]
    fn cancel_all_keeps_entries_for_owner_removal() {
        let table = PeerTable::new();
        let a = lease();
        let b = lease();
        table.register(addr(1), a.clone());
        table.register(addr(2), b.clone());
        table.cancel_all();
        assert!(a.is_cancelled() && b.is_cancelled());
        assert_eq!(table.len(), 2);
        assert!(table.remove_current(addr(1), &a));
        assert!(table.remove_current(addr(2), &b));
        assert!(table.is_empty());
    }

    #[test]
    fn infos_and_sessions_follow_connection_order() {
        let table = PeerTable::new();
        let leases: Vec<PeerLease> = (0..5).map(|_| lease()).collect();
        for (port, lease) in (10..15).rev().zip(leases.iter()) {
            table.register(addr(port), lease.clone());
            table.publish_info(addr(port), lease, info(addr(port), i32::from(port)));
        }
        let ports: Vec<u16> = table.infos().iter().map(|info| info.addr.port()).collect();
        assert_eq!(ports, vec![14, 13, 12, 11, 10]);
        let session_ports: Vec<u16> = table.sessions().iter().map(|s| s.addr.port()).collect();
        assert_eq!(session_ports, ports);
    }

    #[test]
    fn disconnect_matching_reports_affected_addresses() {
        let table = PeerTable::new();
        let a = lease();
        let b = lease();
        table.register(addr(1), a.clone());
        table.register(addr(2), b.clone());
        let removed = table.disconnect_matching(|addr, _| addr.port() == 2);
        assert_eq!(removed, vec![addr(2)]);
        assert!(b.is_cancelled());
        assert!(!a.is_cancelled());
        assert_eq!(table.len(), 1);
    }
}
