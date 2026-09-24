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
use std::sync::Arc;

use bitcoin_rs_primitives::Hash256;
use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::connection::{ConnectionId, PeerLease, PeerSource};
use crate::counters::PeerCounters;
use crate::peer_info::{PeerInfo, PeerRole};

/// One live connection joined with its handshake metadata.
#[derive(Clone, Debug)]
pub struct PeerSession {
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Control handle for the connection.
    pub lease: PeerLease,
    /// Handshake metadata, `None` while the handshake is still in progress.
    pub info: Option<PeerInfo>,
    /// Header tips this connection has delivered and the node accepted.
    pub demonstrated_tips: Vec<Hash256>,
}

#[derive(Debug)]
struct Entry {
    lease: PeerLease,
    info: Option<PeerInfo>,
    demonstrated_tips: Vec<Hash256>,
}

/// The table's live entries plus the traffic accounting it retains of
/// dropped ones. Keeping both under the same lock makes removal linearizable
/// for `traffic_totals` readers: a connection's counter set is counted
/// exactly once, either in `map` or in `retired`/`settled_*`.
#[derive(Debug, Default)]
struct TableView {
    map: HashMap<SocketAddr, Entry>,
    /// Counter sets of dropped connections whose teardown may still be in
    /// flight. Shared (`Arc`), so bytes a dying connection records after its
    /// entry left land in `traffic_totals` whenever they settle — a
    /// removal-time snapshot of the count would lose them. Each entry folds
    /// into `settled_*` once the table holds the last `Arc`.
    retired: Vec<Arc<PeerCounters>>,
    /// Final byte counts of fully torn-down retired connections.
    settled_recv: u64,
    settled_sent: u64,
}

impl std::ops::Deref for TableView {
    type Target = HashMap<SocketAddr, Entry>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl std::ops::DerefMut for TableView {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

fn live_sessions_of(entries: &TableView) -> Vec<PeerSource> {
    entries
        .iter()
        .filter(|(_, entry)| !entry.lease.is_cancelled())
        .map(|(addr, entry)| entry.lease.source(*addr))
        .collect()
}

/// Authoritative table of live peer connections keyed by remote address.
#[derive(Debug, Default)]
pub struct PeerTable {
    entries: RwLock<TableView>,
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
                let prior = entries.insert(
                    addr,
                    Entry {
                        lease,
                        info: None,
                        demonstrated_tips: Vec::new(),
                    },
                );
                if let Some(prior) = prior {
                    prior.lease.cancel();
                    Self::retain_traffic(&mut entries, &prior);
                }
                true
            }
            None => {
                entries.insert(
                    addr,
                    Entry {
                        lease,
                        info: None,
                        demonstrated_tips: Vec::new(),
                    },
                );
                false
            }
        }
    }

    /// Live inbound connections, including handshakes that have not
    /// published metadata yet.
    ///
    /// PRE: none.
    /// POST: returns the number of uncancelled leases whose identity is
    ///   inbound.
    /// INVARIANT: the count is always derived from the live entry set; no
    ///   separate inbound counter exists.
    #[must_use]
    pub fn live_inbound_count(&self) -> usize {
        Self::live_inbound_count_of(&self.entries.read())
    }

    fn live_inbound_count_of(entries: &TableView) -> usize {
        entries
            .values()
            .filter(|entry| entry.lease.is_inbound() && !entry.lease.is_cancelled())
            .count()
    }

    /// Reserves an inbound lease if the Core-derived inbound capacity is
    /// available, registering it as the live connection at `addr`.
    ///
    /// PRE: `lease.is_inbound()` and `max_inbound` is the resolved
    ///   automatic-connection remainder.
    /// POST: returns the registered lease only when the live inbound count
    ///   stays below `max_inbound`; otherwise returns `None` and changes no
    ///   table state. A lease at an address that already holds an inbound
    ///   connection replaces and cancels it exactly as [`Self::register`]
    ///   does, which never grows the count.
    /// INVARIANT: the count test and the reservation are one `PeerTable`
    ///   write operation; every reserved lease is counted until its
    ///   identity is removed.
    #[must_use]
    pub fn try_register_inbound(
        &self,
        addr: SocketAddr,
        lease: PeerLease,
        max_inbound: usize,
    ) -> Option<PeerLease> {
        debug_assert!(lease.is_inbound(), "only inbound leases reserve here");
        let mut entries = self.entries.write();
        let grows_count = match entries.get(&addr) {
            Some(current) => {
                if current.lease.same_connection(&lease) {
                    return Some(lease);
                }
                !current.lease.is_inbound()
            }
            None => true,
        };
        if grows_count && Self::live_inbound_count_of(&entries) >= max_inbound {
            return None;
        }
        let prior = entries.insert(
            addr,
            Entry {
                lease: lease.clone(),
                info: None,
                demonstrated_tips: Vec::new(),
            },
        );
        if let Some(prior) = prior {
            prior.lease.cancel();
            Self::retain_traffic(&mut entries, &prior);
        }
        Some(lease)
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

    /// Records that the live connection accepted `tip_hash` and raises its
    /// active-chain credit when `height` is supplied. See P2P-03 in
    /// `docs/contracts/p2p-wire.md`. Returns `false` for a stale or unpublished
    /// connection and `true` for any live published connection.
    pub fn note_announced_tip(
        &self,
        source: PeerSource,
        tip_hash: Hash256,
        height: Option<i32>,
    ) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&source.addr)
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        let Some(info) = entry.info.as_mut() else {
            return false;
        };
        if !entry.demonstrated_tips.contains(&tip_hash) {
            entry.demonstrated_tips.push(tip_hash);
        }
        if let Some(height) = height
            && height > info.best_known_height
        {
            info.best_known_height = height;
            return true;
        }
        true
    }

    /// Replaces the live connection's retained-tip evidence under the same
    /// identity check as `note_announced_tip`. Used by the credit refresh to
    /// drop resolved tips that can no longer raise the active-chain maximum —
    /// see P2P-03 in `docs/contracts/p2p-wire.md`.
    pub fn set_demonstrated_tips(&self, source: PeerSource, tips: Vec<Hash256>) {
        let mut entries = self.entries.write();
        if let Some(entry) = entries
            .get_mut(&source.addr)
            .filter(|entry| entry.lease.is_current(source))
        {
            entry.demonstrated_tips = tips;
        }
    }

    /// Raises the active-chain credit for `source`. See P2P-03 in
    /// `docs/contracts/p2p-wire.md`.
    pub fn note_announced_height(&self, source: PeerSource, height: i32) -> bool {
        let mut entries = self.entries.write();
        match entries.get_mut(&source.addr) {
            Some(entry) if entry.lease.is_current(source) && !entry.lease.is_cancelled() => {
                let Some(info) = entry.info.as_mut() else {
                    return false;
                };
                if height > info.best_known_height {
                    info.best_known_height = height;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Raises the compact-block relay preference for `source` — its live
    /// connection accepted a post-verack `sendcmpct` with a known version.
    /// Returns `false` for a stale or unpublished connection.
    pub fn note_compact_relay(&self, source: PeerSource) -> bool {
        let mut entries = self.entries.write();
        match entries.get_mut(&source.addr) {
            Some(entry) if entry.lease.is_current(source) && !entry.lease.is_cancelled() => {
                let Some(info) = entry.info.as_mut() else {
                    return false;
                };
                info.compact_block_relay = true;
                true
            }
            _ => false,
        }
    }

    /// Reports whether the live published connection at `addr` requested
    /// compact-block relay. Fetch-side eligibility reads this instead of a
    /// stale per-connection guess.
    pub fn compact_relay_of(&self, addr: SocketAddr) -> bool {
        let entries = self.entries.read();
        entries.get(&addr).is_some_and(|entry| {
            entry
                .info
                .as_ref()
                .is_some_and(|info| info.compact_block_relay)
        })
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
            Self::retain_traffic(&mut entries, &removed);
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
                Self::retire(&mut entries, &removed);
            }
        }
        Self::settle_retired(&mut entries);
        targets
    }

    /// Retains a dropped connection's counter set so `traffic_totals` keeps
    /// counting it after the entry is gone; unpublished connections carry no
    /// counters to retain. Shared (`Arc`), so bytes a dying connection records
    /// after its entry left still land in `traffic_totals` whenever they
    /// settle.
    fn retire(entries: &mut TableView, removed: &Entry) {
        if let Some(info) = removed.info.as_ref() {
            entries.retired.push(Arc::clone(&info.counters));
        }
    }

    /// Folds in the final counts of retired connections whose teardown provably
    /// finished — the table holding the last `Arc` means no writer remains, so
    /// their count is final and the list stays bounded. Runs once per removal
    /// batch so batched disconnects stay O(N + |retired|).
    fn settle_retired(entries: &mut TableView) {
        let TableView {
            retired,
            settled_recv,
            settled_sent,
            ..
        } = entries;
        retired.retain(|counters| {
            if Arc::strong_count(counters) == 1 {
                *settled_recv = settled_recv.saturating_add(counters.bytes_recv());
                *settled_sent = settled_sent.saturating_add(counters.bytes_sent());
                false
            } else {
                true
            }
        });
    }

    /// Per-removal retention for single-entry removals: retain the dropped
    /// connection's counter set, then settle retired connections whose
    /// teardown finished.
    fn retain_traffic(entries: &mut TableView, removed: &Entry) {
        Self::retire(entries, removed);
        Self::settle_retired(entries);
    }

    /// Traffic the node can account for — `(received, sent)` bytes: the live
    /// connections' counters plus the retired counters of every connection
    /// the table has dropped, so the total never decreases across disconnects.
    pub fn traffic_totals(&self) -> (u64, u64) {
        let entries = self.entries.read();
        entries
            .values()
            .filter_map(|entry| entry.info.as_ref().map(|info| &info.counters))
            .chain(entries.retired.iter())
            .fold(
                (entries.settled_recv, entries.settled_sent),
                |(recv, sent), counters| {
                    (
                        recv.saturating_add(counters.bytes_recv()),
                        sent.saturating_add(counters.bytes_sent()),
                    )
                },
            )
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

    /// Returns whether the connection that stamped `source` is still live
    /// and uncancelled. A cancelled lease is not a schedulable peer.
    #[must_use]
    pub fn is_current(&self, source: PeerSource) -> bool {
        self.entries
            .read()
            .get(&source.addr)
            .is_some_and(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
    }

    /// Clones the lease of the live, uncancelled connection at `addr`.
    #[must_use]
    pub fn lease(&self, addr: SocketAddr) -> Option<PeerLease> {
        self.entries
            .read()
            .get(&addr)
            .filter(|entry| !entry.lease.is_cancelled())
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

    /// Identity of every live, uncancelled connection.
    ///
    /// PRE: none.
    /// POST: returns one `PeerSource` per live, uncancelled table entry.
    /// INVARIANT: every returned source passes `is_current` at snapshot time.
    #[must_use]
    pub fn live_sessions(&self) -> Vec<PeerSource> {
        live_sessions_of(&self.entries.read())
    }

    /// Runs `operation` on the live-session snapshot while the table read
    /// lock is held, so a same-address replacement cannot register between
    /// the snapshot and the ownership mutation.
    ///
    /// PRE: `operation` does not acquire the peer-table write lock and does
    ///   not read the table again (the read lock is not reentrant).
    /// POST: `operation` observed the complete live set atomically.
    /// INVARIANT: lock order is peer table, then any lock `operation` takes.
    pub fn with_live_sessions(&self, operation: impl FnOnce(&[PeerSource])) {
        let entries = self.entries.read();
        operation(&live_sessions_of(&entries));
    }

    /// Calls `f` with every live lease under the table's read lock.
    pub fn for_each_lease(&self, mut f: impl FnMut(SocketAddr, &PeerLease)) {
        for (addr, entry) in self.entries.read().iter() {
            f(*addr, &entry.lease);
        }
    }

    /// Visits handshake-complete leases and their identity-bound metadata.
    /// Holds table authority through each callback, including an outbound queue
    /// operation, so replacement cannot change the target or relay preference.
    pub(crate) fn for_each_ready_lease(
        &self,
        mut f: impl FnMut(SocketAddr, &PeerLease, &PeerInfo),
    ) {
        for (addr, entry) in self.entries.read().iter() {
            if entry.lease.is_cancelled() {
                continue;
            }
            if let Some(info) = &entry.info {
                f(*addr, &entry.lease, info);
            }
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
                demonstrated_tips: entry.demonstrated_tips.clone(),
            })
            .collect();
        sessions.sort_unstable_by_key(|session| session.lease.connection_id().get());
        sessions
    }

    /// The peer-liveness snapshot every scheduler consumes: handshake-complete
    /// sessions whose leases are not cancelled, ordered by connection
    /// identity. A cancelled lease is not representable as a schedulable
    /// peer.
    #[must_use]
    pub fn usable_peers(&self) -> Vec<PeerSession> {
        let entries = self.entries.read();
        let mut sessions: Vec<PeerSession> = entries
            .iter()
            .filter(|(_, entry)| !entry.lease.is_cancelled() && entry.info.is_some())
            .map(|(addr, entry)| PeerSession {
                addr: *addr,
                lease: entry.lease.clone(),
                info: entry.info.clone(),
                demonstrated_tips: entry.demonstrated_tips.clone(),
            })
            .collect();
        sessions.sort_unstable_by_key(|session| session.lease.connection_id().get());
        sessions
    }

    /// Counts live outbound connections by relay role, including those still
    /// handshaking.
    ///
    /// PRE: none.
    /// POST: `(full_relay, block_relay)` counts of outbound connections;
    ///   inbound connections are never counted.
    /// INVARIANT: a cancelled lease holds no slot, so a dying connection
    ///   cannot keep its role occupied past its own teardown.
    #[must_use]
    pub fn outbound_role_counts(&self) -> (usize, usize) {
        let mut counts = (0_usize, 0_usize);
        for entry in self.entries.read().values() {
            if entry.lease.is_inbound() || entry.lease.is_cancelled() {
                continue;
            }
            match entry.lease.role() {
                PeerRole::FullRelay => counts.0 += 1,
                PeerRole::BlockRelayOnly => counts.1 += 1,
            }
        }
        counts
    }

    /// Returns the current connection source only when `addr` is published as
    /// ready and its lease is not cancelled. Registration clears predecessor
    /// metadata, so a handshaking replacement cannot inherit an old scheduler
    /// decision.
    #[must_use]
    pub fn ready_source(&self, addr: SocketAddr) -> Option<PeerSource> {
        let entries = self.entries.read();
        let entry = entries.get(&addr)?;
        entry.info.as_ref()?;
        if entry.lease.is_cancelled() {
            return None;
        }
        Some(entry.lease.source(addr))
    }

    /// Starts `operation` only for a current, uncancelled source. The table
    /// read lock is held for the whole operation so a same-address replacement
    /// cannot register until the caller finishes.
    pub fn with_current(&self, source: PeerSource, operation: impl FnOnce()) -> bool {
        let entries = self.entries.read();
        if !entries
            .get(&source.addr)
            .is_some_and(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        {
            return false;
        }
        operation();
        true
    }

    /// Clones the lease only when it is still the connection identified by
    /// `source` and has not been cancelled.
    #[must_use]
    pub fn lease_source(&self, source: PeerSource) -> Option<PeerLease> {
        self.entries
            .read()
            .get(&source.addr)
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
            .map(|entry| entry.lease.clone())
    }

    /// Sends only to the current, uncancelled connection, holding its
    /// identity through the nonblocking enqueue. A replacement cannot
    /// register between validation and enqueue; saturation retains the
    /// lease's cancellation policy.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, source: PeerSource, message: crate::Message) -> Result<(), crate::Message> {
        let entries = self.entries.read();
        let Some(entry) = entries
            .get(&source.addr)
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return Err(message);
        };
        entry.lease.send(message).map_err(|error| error.0)
    }

    /// Like [`Self::send`], then runs `published` while the connection's
    /// identity is still held: a same-address replacement cannot register
    /// between the enqueue and the caller stamping request ownership under
    /// that identity.
    #[allow(clippy::result_large_err)]
    pub fn send_then(
        &self,
        source: PeerSource,
        message: crate::Message,
        published: impl FnOnce(),
    ) -> Result<(), crate::Message> {
        let entries = self.entries.read();
        let Some(entry) = entries
            .get(&source.addr)
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return Err(message);
        };
        entry.lease.send(message).map_err(|error| error.0)?;
        published();
        Ok(())
    }

    /// Snapshots handshake-complete peers together with the connection that
    /// published them.
    #[must_use]
    pub fn ready_peers(&self) -> Vec<crate::connection::ReadyPeer> {
        self.sessions()
            .into_iter()
            .filter(|session| !session.lease.is_cancelled())
            .filter_map(|session| {
                Some(crate::connection::ReadyPeer {
                    source: session.lease.source(session.addr),
                    info: session.info?,
                })
            })
            .collect()
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
        info_with_counters(
            addr,
            start_height,
            std::sync::Arc::new(crate::counters::PeerCounters::default()),
        )
    }

    fn info_with_counters(
        addr: SocketAddr,
        start_height: i32,
        counters: std::sync::Arc<crate::counters::PeerCounters>,
    ) -> PeerInfo {
        PeerInfo {
            addr,
            version: 70016,
            wtxid_relay: false,
            compact_block_relay: false,
            services: 0,
            user_agent: String::new(),
            start_height,
            best_known_height: start_height,
            conn_time: 0,
            inbound: false,
            addr_bind: addr,
            time_offset: 0,
            counters,
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

    fn inbound_lease() -> PeerLease {
        let (tx, _rx) = crossbeam_channel::unbounded();
        PeerLease::new_inbound(tx)
    }

    #[test]
    fn try_register_inbound_refuses_at_zero_capacity() {
        let table = PeerTable::new();
        let lease = inbound_lease();
        assert!(
            table.try_register_inbound(addr(1), lease, 0).is_none(),
            "zero capacity refuses"
        );
        assert!(table.is_empty(), "a refusal changes no table state");
    }

    #[test]
    fn try_register_inbound_admits_below_the_cap_only() {
        let table = PeerTable::new();
        let first = inbound_lease();
        assert!(table.try_register_inbound(addr(1), first, 1).is_some());
        // The unpublished (handshaking) lease already occupies capacity.
        assert_eq!(table.live_inbound_count(), 1);
        let second = inbound_lease();
        assert!(
            table
                .try_register_inbound(addr(2), second.clone(), 1)
                .is_none()
        );
        assert!(!second.is_cancelled(), "a refusal cancels nothing");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn live_inbound_count_ignores_outbound_leases() {
        let table = PeerTable::new();
        table.register(addr(1), lease());
        assert_eq!(table.live_inbound_count(), 0);
        assert!(
            table
                .try_register_inbound(addr(2), inbound_lease(), 1)
                .is_some()
        );
        assert_eq!(table.live_inbound_count(), 1);
    }

    #[test]
    fn removal_releases_inbound_capacity() -> Result<(), Box<dyn std::error::Error>> {
        let table = PeerTable::new();
        let registered = table
            .try_register_inbound(addr(1), inbound_lease(), 1)
            .ok_or("capacity must admit the first inbound lease")?;
        assert!(table.remove_current(addr(1), &registered));
        assert_eq!(table.live_inbound_count(), 0);
        assert!(
            table
                .try_register_inbound(addr(2), inbound_lease(), 1)
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn inbound_replacement_at_capacity_keeps_the_count_and_cancels_the_predecessor() {
        let table = PeerTable::new();
        let first = inbound_lease();
        assert!(
            table
                .try_register_inbound(addr(1), first.clone(), 1)
                .is_some(),
            "capacity must admit the first inbound lease"
        );
        assert!(
            table
                .try_register_inbound(addr(1), inbound_lease(), 1)
                .is_some(),
            "a same-address replacement never grows the count and is admitted at capacity"
        );
        assert!(first.is_cancelled());
        assert_eq!(table.live_inbound_count(), 1);
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

    // P2P-02: source-checked operations reject replacements and already-cancelled leases.
    #[test]
    fn with_current_rejects_stale_source_and_holds_live_identity() {
        let table = PeerTable::new();
        let (stale_tx, stale_rx) = crossbeam_channel::unbounded();
        let (current_tx, current_rx) = crossbeam_channel::unbounded();
        let stale = PeerLease::new(stale_tx);
        let current = PeerLease::new(current_tx);
        table.register(addr(1), stale.clone());
        let stale_source = stale.source(addr(1));
        table.register(addr(1), current.clone());
        let current_source = current.source(addr(1));

        let mut called = false;
        assert!(!table.with_current(stale_source, || called = true));
        assert!(!called);
        assert!(table.with_current(current_source, || {
            // A replacement needs this write lock. Queueing while the
            // operation holds table authority must linearize before it.
            assert!(table.entries.try_write().is_none());
            assert!(current.send(crate::Message::Ping(1)).is_ok());
            called = true;
        }));
        assert!(called);
        assert!(matches!(current_rx.try_recv(), Ok(crate::Message::Ping(1))));
        assert!(table.send(stale_source, crate::Message::Ping(1)).is_err());
        assert!(stale_rx.try_recv().is_err());
        assert!(table.send(current_source, crate::Message::Ping(2)).is_ok());
        assert!(matches!(current_rx.try_recv(), Ok(crate::Message::Ping(2))));

        current.cancel();
        assert!(table.send(current_source, crate::Message::Ping(3)).is_err());
        assert!(current_rx.try_recv().is_err());
        assert!(!table.with_current(current_source, || panic!("cancelled source")));
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

    // Contract proof: P2P-03 (docs/contracts/p2p-wire.md).
    #[test]
    fn note_announced_height_credits_only_the_delivering_connection() {
        let table = PeerTable::new();
        let (stale_tx, _stale_rx) = crossbeam_channel::unbounded();
        let stale = PeerLease::new(stale_tx);
        table.register(addr(1), stale.clone());
        let stale_source = stale.source(addr(1));

        // Same-address replacement: the stale connection is cancelled and
        // the new connection takes the slot.
        let (current_tx, _current_rx) = crossbeam_channel::unbounded();
        let current = PeerLease::new(current_tx);
        table.register(addr(1), current.clone());
        let current_source = current.source(addr(1));
        assert!(table.publish_info(addr(1), &current, info(addr(1), 10)));

        // The stale source must not inherit the replacement's credit slot.
        assert!(!table.note_announced_height(stale_source, 42));
        assert_eq!(table.infos()[0].best_known_height, 10);

        // The live connection raises the entry it owns.
        assert!(table.note_announced_height(current_source, 42));
        assert_eq!(table.infos()[0].best_known_height, 42);
    }

    // Contract proof: P2P-03 (docs/contracts/p2p-wire.md).
    #[test]
    fn note_announced_height_raises_monotonically_and_reports_actual_updates() {
        let table = PeerTable::new();
        let current = lease();
        table.register(addr(1), current.clone());
        let source = current.source(addr(1));
        assert!(table.publish_info(addr(1), &current, info(addr(1), 10)));

        // Equal height: no update.
        assert!(!table.note_announced_height(source, 10));
        assert_eq!(table.infos()[0].best_known_height, 10);

        // Lower height: no update (monotonic).
        assert!(!table.note_announced_height(source, 9));
        assert_eq!(table.infos()[0].best_known_height, 10);

        // Higher height: update.
        assert!(table.note_announced_height(source, 12));
        assert_eq!(table.infos()[0].best_known_height, 12);

        // Accepted-tip evidence is retained with the live connection so the
        // node can re-evaluate it if a later fork becomes active.
        let demonstrated_tip = Hash256::from_le_bytes(&[7_u8; 32]);
        assert!(table.note_announced_tip(source, demonstrated_tip, Some(13)));
        assert_eq!(table.infos()[0].best_known_height, 13);
        assert_eq!(
            table.sessions()[0].demonstrated_tips,
            vec![demonstrated_tip]
        );

        // Unknown address: no update.
        let other = lease();
        let other_source = other.source(addr(2));
        assert!(!table.note_announced_height(other_source, 99));

        // Registered but unpublished peer: no update.
        table.register(addr(3), lease());
        let Some(unpublished) = table.lease(addr(3)) else {
            return;
        };
        let unpublished_source = unpublished.source(addr(3));
        assert!(!table.note_announced_height(unpublished_source, 50));
    }

    // CONTRACT: docs/policies/p2p-compatibility.md#4-handshake-contract (the
    // published BIP152 relay preference feeds compact-fetch eligibility).
    #[test]
    fn note_compact_relay_credits_only_the_delivering_connection() {
        let table = PeerTable::new();
        let (stale_tx, _stale_rx) = crossbeam_channel::unbounded();
        let stale = PeerLease::new(stale_tx);
        table.register(addr(1), stale.clone());
        let stale_source = stale.source(addr(1));

        // Same-address replacement: the stale connection is cancelled and
        // the new connection takes the slot.
        let (current_tx, _current_rx) = crossbeam_channel::unbounded();
        let current = PeerLease::new(current_tx);
        table.register(addr(1), current.clone());
        let current_source = current.source(addr(1));
        assert!(table.publish_info(addr(1), &current, info(addr(1), 10)));

        // The stale connection cannot raise the replacement's preference.
        assert!(!table.note_compact_relay(stale_source));
        assert!(!table.compact_relay_of(addr(1)));

        // The live connection raises its own entry.
        assert!(table.note_compact_relay(current_source));
        assert!(table.compact_relay_of(addr(1)));

        // Unknown and unpublished addresses never report relay.
        assert!(!table.compact_relay_of(addr(2)));
        table.register(addr(3), lease());
        assert!(!table.compact_relay_of(addr(3)));
    }

    // `getnettotals` contract: totals persist across every removal path and
    // keep counting bytes a dying connection records after its entry left.
    #[test]
    fn traffic_totals_stay_monotonic_across_removals() {
        use std::io::{Cursor, Write as _};

        fn counted(
            counters: &Arc<crate::counters::PeerCounters>,
        ) -> crate::counters::CountingStream<Cursor<Vec<u8>>> {
            crate::counters::CountingStream::new(Cursor::new(Vec::new()), Arc::clone(counters))
        }

        let table = PeerTable::new();
        assert_eq!(table.traffic_totals(), (0, 0));

        // Same-address replacement retires the predecessor's counters.
        let first = lease();
        let counters_first = Arc::new(crate::counters::PeerCounters::default());
        table.register(addr(1), first.clone());
        table.publish_info(
            addr(1),
            &first,
            info_with_counters(addr(1), 1, counters_first.clone()),
        );
        assert!(counted(&counters_first).write_all(&[0_u8; 10]).is_ok());
        assert_eq!(table.traffic_totals(), (0, 10));

        let second = lease();
        assert!(table.register(addr(1), second.clone()));
        assert_eq!(table.traffic_totals(), (0, 10));

        // disconnect() retires counters; bytes the dying connection records
        // after its entry left still land in the totals.
        let counters_second = Arc::new(crate::counters::PeerCounters::default());
        table.publish_info(
            addr(1),
            &second,
            info_with_counters(addr(1), 2, counters_second.clone()),
        );
        let mut stream_second = counted(&counters_second);
        assert!(stream_second.write_all(&[0_u8; 20]).is_ok());
        assert_eq!(table.traffic_totals(), (0, 30));
        assert!(table.disconnect(addr(1)));
        assert!(stream_second.write_all(&[0_u8; 5]).is_ok());
        assert_eq!(table.traffic_totals(), (0, 35));

        // disconnect_matching retires counters too.
        let third = lease();
        let counters_third = Arc::new(crate::counters::PeerCounters::default());
        table.register(addr(2), third.clone());
        table.publish_info(
            addr(2),
            &third,
            info_with_counters(addr(2), 3, counters_third.clone()),
        );
        assert!(counted(&counters_third).write_all(&[0_u8; 7]).is_ok());
        let removed = table.disconnect_matching(|addr, _| addr.port() == 2);
        assert_eq!(removed, vec![addr(2)]);
        assert_eq!(table.traffic_totals(), (0, 42));

        // Fully torn-down counters fold into settled totals, bounding the
        // retired list, and nothing already counted is lost.
        drop(stream_second);
        drop(counters_first);
        drop(counters_second);
        drop(counters_third);
        let fourth = lease();
        table.register(addr(3), fourth);
        assert!(table.disconnect(addr(3)));
        assert!(table.entries.read().retired.is_empty());
        assert_eq!(table.traffic_totals(), (0, 42));
    }

    /// Slot arithmetic counts outbound connections by relay role. Inbound
    /// connections and cancelled leases hold no outbound slot.
    #[test]
    fn outbound_role_counts_split_by_relay_role() {
        let table = PeerTable::new();
        let (full_tx, _full_rx) = crossbeam_channel::unbounded();
        table.register(addr(1), PeerLease::new(full_tx));
        let (second_full_tx, _second_full_rx) = crossbeam_channel::unbounded();
        table.register(addr(2), PeerLease::new(second_full_tx));
        let (block_tx, _block_rx) = crossbeam_channel::unbounded();
        table.register(addr(3), PeerLease::new_block_relay(block_tx));
        let (inbound_tx, _inbound_rx) = crossbeam_channel::unbounded();
        table.register(addr(4), PeerLease::new_inbound(inbound_tx));
        let (dead_tx, _dead_rx) = crossbeam_channel::unbounded();
        let cancelled = PeerLease::new(dead_tx);
        cancelled.cancel();
        table.register(addr(5), cancelled);

        assert_eq!(
            table.outbound_role_counts(),
            (2, 1),
            "two full-relay and one block-relay outbound connection"
        );
    }
}
