//! Live peer-session table: the single owner of connection leases and the
//! handshake metadata published for them.

use crate::{PeerEndpoint, PeerRemote};
use std::hash::{BuildHasher, RandomState};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_primitives::{Hash256, Txid, Wtxid};
use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::connection::{ConnectionId, OutboundRefusal, PeerLease, PeerSource};
use crate::counters::PeerCounters;
use crate::peer::CompactBlockNegotiation;
use crate::peer_info::PeerInfo;
#[cfg(test)]
use crate::peer_info::PeerRole;

#[derive(Clone, Debug)]
pub struct PeerSession {
    pub endpoint: Option<PeerEndpoint>,
    pub addr: PeerRemote,
    pub lease: PeerLease,
    pub info: Option<PeerInfo>,
    pub(crate) demonstrated_tips: Vec<Hash256>,
    pub(crate) headers_horizon: Option<u32>,
    /// compact-block push — Core's `getpeerinfo.bip152_hb_to`: we asked the
    /// peer (via `sendcmpct(true)`) to announce new blocks to us as
    /// unsolicited `cmpctblock` instead of `inv`.
    pub bip152_hb_to: bool,
    /// push — Core's `getpeerinfo.bip152_hb_from`: the peer asked us (via
    /// its `sendcmpct(true)`) to announce new blocks to it as unsolicited
    /// `cmpctblock` instead of `inv`.
    pub bip152_hb_from: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PeerAnnouncementState {
    pub(crate) last_announced_block: Option<Hash256>,
    pub(crate) compact_high_bandwidth: Option<bool>,
    pub(crate) compact_version: Option<u64>,
    pub(crate) useful_block_sequence: u64,
    /// high-bandwidth push (`bip152_hb_to`). Selection authority lives in
    /// the worker; the table is the snapshot rpc reads, so promotions and
    /// demotions are written through here.
    pub(crate) selected_high_bandwidth: bool,
    /// Whether this peer negotiated BIP332 stale-tip relay, and its `prefers_blocks` flag.
    pub(crate) stale_tip_prefers_blocks: Option<bool>,
    /// The BIP331 `PKG_RELAY_*` bits the connection owner negotiated; `0`
    pub(crate) package_relay: u64,
}

#[derive(Debug)]
struct Entry {
    lease: PeerLease,
    info: Option<PeerInfo>,
    demonstrated_tips: Vec<Hash256>,
    headers_horizon: Option<u32>,
    announcement: PeerAnnouncementState,
    keyed_netgroup: u64,
    useful_tx_sequence: u64,
    #[cfg(test)]
    onion_epoch: Option<u64>,
}

impl Entry {
    fn fresh(lease: PeerLease) -> Self {
        Self {
            lease,
            info: None,
            demonstrated_tips: Vec::new(),
            headers_horizon: None,
            announcement: PeerAnnouncementState::default(),
            keyed_netgroup: 0,
            useful_tx_sequence: 0,
            #[cfg(test)]
            onion_epoch: None,
        }
    }

    fn session(&self, addr: PeerRemote) -> PeerSession {
        PeerSession {
            endpoint: addr.endpoint(),
            addr,
            lease: self.lease.clone(),
            info: self.info.clone(),
            demonstrated_tips: self.demonstrated_tips.clone(),
            headers_horizon: self.headers_horizon,
            bip152_hb_to: self.announcement.selected_high_bandwidth,
            bip152_hb_from: self.announcement.compact_high_bandwidth == Some(true),
        }
    }
}

#[derive(Debug, Default)]
struct TableView {
    map: HashMap<PeerRemote, Entry>,
    retired: Vec<Arc<PeerCounters>>,
    settled_recv: u64,
    settled_sent: u64,
}

impl std::ops::Deref for TableView {
    type Target = HashMap<PeerRemote, Entry>;

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
        .map(|(key, entry)| entry.lease.source(key.endpoint()))
        .collect()
}

#[derive(Debug, Default)]
pub struct PeerTable {
    entries: RwLock<TableView>,
    next_useful_block_sequence: AtomicU64,
    next_useful_tx_sequence: AtomicU64,
    netgroup_key: RandomState,
    pub(crate) tx_policy: parking_lot::Mutex<crate::tx_policy::TxPolicy>,
}

impl PeerTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn cancel_transport_epoch(&self, epoch: &Arc<AtomicBool>) {
        for entry in self.entries.read().values() {
            if entry.lease.belongs_to_transport_epoch(epoch) {
                entry.lease.cancel();
            }
        }
    }

    pub fn register(&self, addr: impl Into<PeerRemote>, lease: PeerLease) -> bool {
        let addr = addr.into();
        Self::register_locked(&mut self.entries.write(), addr, Entry::fresh(lease))
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn register_unidentified(&self, lease: PeerLease) -> bool {
        let key = PeerRemote::AnonymousTor(lease.connection_id());
        let entry = Entry {
            keyed_netgroup: self
                .netgroup_key
                .hash_one(crate::endpoint::anonymous_netgroup(lease.connection_id())),
            ..Entry::fresh(lease)
        };
        Self::register_locked(&mut self.entries.write(), key, entry)
    }

    fn register_locked(entries: &mut TableView, addr: PeerRemote, entry: Entry) -> bool {
        match entries.get(&addr) {
            Some(current) if current.lease.same_connection(&entry.lease) => false,
            Some(_) => {
                let prior = entries.insert(addr, entry);
                if let Some(prior) = prior {
                    prior.lease.cancel();
                    Self::retain_traffic(entries, &prior);
                }
                true
            }
            None => {
                entries.insert(addr, entry);
                false
            }
        }
    }

    pub(crate) fn try_register_outbound(
        &self,
        addr: impl Into<PeerRemote>,
        lease: PeerLease,
        activity: &crate::NetworkActivity,
    ) -> Option<PeerLease> {
        let addr = addr.into();
        debug_assert!(!lease.is_inbound(), "only outbound leases register here");
        let mut entries = self.entries.write();
        if !activity.is_active() || lease.is_cancelled() {
            return None;
        }
        Self::register_locked(&mut entries, addr, Entry::fresh(lease.clone()));
        Some(lease)
    }

    /// INVARIANT: the count is always derived from the live entry set; no
    ///   separate inbound counter exists.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn live_inbound_count(&self) -> usize {
        Self::live_inbound_count_of(&self.entries.read())
    }

    fn live_inbound_count_of(entries: &TableView) -> usize {
        entries
            .values()
            .filter(|entry| entry.lease.is_inbound() && !entry.lease.is_cancelled())
            .count()
    }

    /// INVARIANT: the activity/count tests, eviction and reservation are one
    ///   `PeerTable` write operation; every reserved lease is counted until
    ///   its identity is removed.
    #[must_use]
    pub(crate) fn try_register_inbound(
        &self,
        addr: impl Into<PeerRemote>,
        lease: PeerLease,
        netgroup: &[u8],
        max_inbound: usize,
        best_block_depth: u64,
        activity: &crate::NetworkActivity,
    ) -> Option<PeerLease> {
        let addr = addr.into();
        debug_assert!(lease.is_inbound(), "only inbound leases reserve here");
        let mut entries = self.entries.write();
        if !activity.is_active() || lease.is_cancelled() {
            return None;
        }
        let key = addr;
        let grows_count = match entries.get(&key) {
            Some(current) => {
                if current.lease.same_connection(&lease) {
                    return Some(lease);
                }
                !current.lease.is_inbound() || current.lease.is_cancelled()
            }
            None => true,
        };
        if grows_count
            && Self::live_inbound_count_of(&entries) >= max_inbound
            && !Self::evict_inbound_locked(&mut entries, key, best_block_depth)
        {
            return None;
        }
        let entry = Entry {
            keyed_netgroup: self.netgroup_key.hash_one(netgroup),
            ..Entry::fresh(lease.clone())
        };
        Self::register_locked(&mut entries, key, entry);
        Some(lease)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn try_register_inbound_unidentified(
        &self,
        lease: PeerLease,
        max_inbound: usize,
        best_block_depth: u64,
        activity: &crate::NetworkActivity,
        onion_epoch: Option<u64>,
    ) -> Option<PeerLease> {
        debug_assert!(lease.is_inbound(), "only inbound leases reserve here");
        let mut entries = self.entries.write();
        if !activity.is_active() {
            return None;
        }
        let key = PeerRemote::AnonymousTor(lease.connection_id());
        if entries
            .get(&key)
            .is_some_and(|c| c.lease.same_connection(&lease))
        {
            return Some(lease);
        }
        if Self::live_inbound_count_of(&entries) >= max_inbound
            && !Self::evict_inbound_locked(&mut entries, key, best_block_depth)
        {
            return None;
        }
        let entry = Entry {
            keyed_netgroup: self
                .netgroup_key
                .hash_one(crate::endpoint::anonymous_netgroup(lease.connection_id())),
            onion_epoch,
            ..Entry::fresh(lease.clone())
        };
        Self::register_locked(&mut entries, key, entry);
        Some(lease)
    }

    fn evict_inbound_locked(
        entries: &mut TableView,
        addr: PeerRemote,
        best_block_depth: u64,
    ) -> bool {
        if entries
            .get(&addr)
            .is_some_and(|current| !current.lease.is_inbound() && !current.lease.is_cancelled())
        {
            return false;
        }
        let candidates = entries
            .iter()
            .filter_map(|(addr, entry)| Self::eviction_candidate(*addr, entry, best_block_depth))
            .collect();
        let Some(victim_id) = crate::eviction::select_inbound_to_evict(candidates) else {
            return false;
        };
        let Some(victim) = entries
            .iter()
            .find(|(key, _)| **key == victim_id)
            .map(|(key, _)| *key)
        else {
            return false;
        };
        if let Some(removed) = entries.remove(&victim) {
            removed.lease.cancel();
            Self::retain_traffic(entries, &removed);
        }
        tracing::debug!(peer_key = ?victim, "inbound slots full; evicted a connection for a new inbound peer");
        true
    }

    fn eviction_candidate(
        addr: PeerRemote,
        entry: &Entry,
        best_block_depth: u64,
    ) -> Option<crate::eviction::EvictionCandidate> {
        let lease = &entry.lease;
        if !lease.is_inbound() || lease.is_cancelled() || lease.is_no_ban() {
            return None;
        }
        let info = entry.info.as_ref();
        Some(crate::eviction::EvictionCandidate {
            addr,
            connected: lease.connected_at(),
            last_block: entry.announcement.useful_block_sequence,
            last_tx: entry.useful_tx_sequence,
            relevant_services: info.is_some_and(|info| {
                crate::listener::has_all_desirable_service_flags(
                    ServiceFlags::from(info.services),
                    best_block_depth,
                )
            }),
            relay_txs: info.is_some_and(|info| info.relay_transactions),
            keyed_netgroup: entry.keyed_netgroup,
            is_local: addr
                .endpoint()
                .is_some_and(|endpoint| crate::discouragement::is_local(endpoint.address())),
        })
    }

    pub(crate) fn set_network_active(&self, flag: &AtomicBool, active: bool) {
        let entries = self.entries.write();
        flag.store(active, Ordering::Release);
        if !active {
            for entry in entries.values() {
                entry.lease.cancel();
            }
        }
    }

    pub fn publish_info_unidentified(&self, lease: &PeerLease, info: PeerInfo) -> bool {
        self.publish_info(PeerRemote::AnonymousTor(lease.connection_id()), lease, info)
    }

    pub fn publish_info(
        &self,
        addr: impl Into<PeerRemote>,
        lease: &PeerLease,
        info: PeerInfo,
    ) -> bool {
        let addr = addr.into();
        let mut entries = self.entries.write();
        match entries.get_mut(&addr) {
            Some(entry) if entry.lease.same_connection(lease) => {
                entry.info = Some(info);
                true
            }
            _ => false,
        }
    }

    pub(crate) fn note_announced_tip(
        &self,
        source: PeerSource,
        tip_hash: Hash256,
        height: Option<i32>,
    ) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
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

    pub(crate) fn set_demonstrated_tips(&self, source: PeerSource, tips: Vec<Hash256>) {
        let mut entries = self.entries.write();
        if let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source))
        {
            entry.demonstrated_tips = tips;
        }
    }

    pub(crate) fn note_announced_height(&self, source: PeerSource, height: i32) -> bool {
        let mut entries = self.entries.write();
        match entries.get_mut(&PeerRemote::from(source)) {
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

    pub(crate) fn note_headers_horizon(&self, source: PeerSource, height: u32) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        if entry.info.is_none() {
            return false;
        }
        entry.headers_horizon = Some(entry.headers_horizon.map_or(height, |cap| cap.min(height)));
        true
    }

    pub(crate) fn note_headers_progress(&self, source: PeerSource, height: u32) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        if entry.info.is_none() {
            return false;
        }
        if entry.headers_horizon.is_some_and(|cap| height > cap) {
            entry.headers_horizon = None;
        }
        true
    }

    /// Publishes the BIP331 `PKG_RELAY_*` bits the connection owner negotiated
    /// INVARIANT: the `Peer` stays the one owner of the negotiation; this is
    ///   a copy of its answer.
    pub(crate) fn note_package_relay(&self, source: PeerSource, versions: u64) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.announcement.package_relay = versions;
        true
    }

    pub fn package_relay_versions(&self, source: bitcoin_rs_mempool::PeerToken) -> u64 {
        self.entries
            .read()
            .iter()
            .find_map(|(key, entry)| {
                if entry.lease.is_cancelled() {
                    return None;
                }
                let current = entry.lease.source(key.endpoint());
                (current.endpoint() == source.endpoint
                    && current.connection_id().get() == source.connection_id)
                    .then_some(entry.announcement.package_relay)
            })
            .unwrap_or(0)
    }

    pub fn request_package_info_from_token(
        &self,
        source: bitcoin_rs_mempool::PeerToken,
        subject: Wtxid,
        parents: &[Txid],
    ) -> bool {
        let source = self.entries.read().iter().find_map(|(key, entry)| {
            let current = entry.lease.source(key.endpoint());
            (current.endpoint() == source.endpoint
                && current.connection_id().get() == source.connection_id
                && !entry.lease.is_cancelled())
            .then_some(current)
        });
        source.is_some_and(|source| self.request_package_info(source, subject, parents))
    }

    #[cfg(feature = "test-seam")]
    pub fn seed_package_relay(&self, source: PeerSource, versions: u64) -> bool {
        self.note_package_relay(source, versions)
    }

    /// Records that the live connection negotiated BIP332 stale-tip relay
    /// with the remote peer's `prefers_blocks` preference.
    pub(crate) fn note_stale_tip_relay(&self, source: PeerSource, prefers_blocks: bool) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.announcement.stale_tip_prefers_blocks = Some(prefers_blocks);
        true
    }

    pub(crate) fn note_compact_relay(&self, source: PeerSource) -> bool {
        let mut entries = self.entries.write();
        match entries.get_mut(&PeerRemote::from(source)) {
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

    pub(crate) fn note_compact_announcement(
        &self,
        source: PeerSource,
        negotiation: &CompactBlockNegotiation,
    ) -> bool {
        let Some(preference) = negotiation.remote_preference() else {
            return false;
        };
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.announcement.compact_high_bandwidth = Some(preference.send_compact);
        entry.announcement.compact_version = Some(preference.version);
        true
    }

    pub(crate) fn note_announced_block(&self, source: PeerSource, hash: Hash256) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.announcement.last_announced_block = Some(hash);
        true
    }

    pub(crate) fn note_useful_block(&self, source: PeerSource) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.announcement.useful_block_sequence = self
            .next_useful_block_sequence
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        true
    }

    pub fn note_useful_transaction(&self, source: PeerSource) -> bool {
        let mut entries = self.entries.write();
        let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return false;
        };
        entry.useful_tx_sequence = self
            .next_useful_tx_sequence
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        true
    }

    /// connection for high-bandwidth compact-block push (`bip152_hb_to`).
    pub(crate) fn note_high_bandwidth_selected(&self, source: PeerSource, selected: bool) {
        let mut entries = self.entries.write();
        if let Some(entry) = entries
            .get_mut(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        {
            entry.announcement.selected_high_bandwidth = selected;
        }
    }

    pub(crate) fn announcement_state(&self, source: PeerSource) -> Option<PeerAnnouncementState> {
        let entries = self.entries.read();
        entries.get(&PeerRemote::from(source)).and_then(|entry| {
            (entry.lease.is_current(source) && entry.info.is_some()).then_some(entry.announcement)
        })
    }

    #[cfg(test)]
    pub(crate) fn compact_relay_of(&self, addr: impl Into<PeerRemote>) -> bool {
        let addr = addr.into();
        let entries = self.entries.read();
        entries.get(&addr).is_some_and(|entry| {
            entry
                .info
                .as_ref()
                .is_some_and(|info| info.compact_block_relay)
        })
    }

    pub(crate) fn compact_relay_of_source(&self, source: PeerSource) -> bool {
        let entries = self.entries.read();
        entries
            .get(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
            .is_some_and(|entry| {
                entry
                    .info
                    .as_ref()
                    .is_some_and(|info| info.compact_block_relay)
            })
    }

    /// Records that the live connection at `source` negotiated BIP130 `sendheaders`.
    pub(crate) fn note_send_headers(&self, source: PeerSource) -> bool {
        let mut entries = self.entries.write();
        match entries.get_mut(&PeerRemote::from(source)) {
            Some(entry) if entry.lease.is_current(source) && !entry.lease.is_cancelled() => {
                let Some(info) = entry.info.as_mut() else {
                    return false;
                };
                info.send_headers = true;
                true
            }
            _ => false,
        }
    }

    pub fn remove_current(&self, addr: impl Into<PeerRemote>, lease: &PeerLease) -> bool {
        let addr = addr.into();
        self.remove_if(addr, |current| current.same_connection(lease))
    }

    pub fn remove_unidentified(&self, lease: &PeerLease) -> bool {
        self.remove_if(PeerRemote::AnonymousTor(lease.connection_id()), |current| {
            current.same_connection(lease)
        })
    }

    pub(crate) fn disconnect_source(&self, source: PeerSource) -> bool {
        self.remove_if(PeerRemote::from(source), |current| {
            current.is_current(source)
        })
    }

    pub fn disconnect(&self, addr: impl Into<PeerRemote>) -> bool {
        let addr = addr.into();
        self.remove_if(addr, |_| true)
    }

    pub fn disconnect_ready(&self, addr: impl Into<PeerRemote>) -> bool {
        self.remove_entry_if(addr.into(), |entry| entry.info.is_some())
    }

    pub(crate) fn disconnect_connection(&self, addr: PeerEndpoint, id: ConnectionId) -> bool {
        self.remove_if(addr.into(), |current| current.connection_id() == id)
    }

    /// INVARIANT: address sessions are not consulted for identity, so the
    ///   endpoint-keyed replacement rule plays no part here.
    pub fn disconnect_ready_node_id(&self, node_id: u64) -> bool {
        let mut entries = self.entries.write();
        let Some(key) = entries
            .iter()
            .find(|(_, entry)| entry.info.is_some() && entry.lease.node_id() == node_id)
            .map(|(key, _)| *key)
        else {
            return false;
        };
        Self::remove_locked(&mut entries, key);
        true
    }

    pub fn disconnect_ready_node_id_at(&self, addr: impl Into<PeerRemote>, node_id: u64) -> bool {
        self.remove_entry_if(addr.into(), |entry| {
            entry.info.is_some() && entry.lease.node_id() == node_id
        })
    }

    fn remove_if(&self, addr: PeerRemote, matches: impl FnOnce(&PeerLease) -> bool) -> bool {
        self.remove_entry_if(addr, |entry| matches(&entry.lease))
    }

    fn remove_entry_if(&self, addr: PeerRemote, matches: impl FnOnce(&Entry) -> bool) -> bool {
        let mut entries = self.entries.write();
        if !entries.get(&addr).is_some_and(matches) {
            return false;
        }
        Self::remove_locked(&mut entries, addr);
        true
    }

    pub(crate) fn disconnect_matching(
        &self,
        predicate: impl Fn(&PeerRemote, &PeerLease) -> bool,
    ) -> Vec<PeerRemote> {
        let mut entries = self.entries.write();
        let targets: Vec<PeerRemote> = entries
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

    fn remove_locked(entries: &mut TableView, key: PeerRemote) {
        if let Some(removed) = entries.remove(&key) {
            removed.lease.cancel();
            Self::retain_traffic(entries, &removed);
        }
    }
    #[cfg(test)]
    pub(crate) fn disconnect_onion_epoch(&self, epoch: u64) -> Vec<ConnectionId> {
        let mut entries = self.entries.write();
        let targets: Vec<(PeerRemote, ConnectionId)> = entries
            .iter()
            .filter(|(addr, entry)| {
                matches!(addr, PeerRemote::AnonymousTor(_)) && entry.onion_epoch == Some(epoch)
            })
            .map(|(addr, entry)| (*addr, entry.lease.connection_id()))
            .collect();
        for (addr, _) in &targets {
            if let Some(removed) = entries.remove(addr) {
                removed.lease.cancel();
                Self::retire(&mut entries, &removed);
            }
        }
        Self::settle_retired(&mut entries);
        targets.into_iter().map(|(_, id)| id).collect()
    }

    fn retire(entries: &mut TableView, removed: &Entry) {
        if let Some(info) = removed.info.as_ref() {
            entries.retired.push(Arc::clone(&info.counters));
        }
    }

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

    fn retain_traffic(entries: &mut TableView, removed: &Entry) {
        Self::retire(entries, removed);
        Self::settle_retired(entries);
    }

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

    pub fn cancel_all(&self) {
        for entry in self.entries.read().values() {
            entry.lease.cancel();
        }
    }

    #[must_use]
    pub fn is_connected(&self, addr: impl Into<PeerRemote>) -> bool {
        let addr = addr.into();
        self.entries.read().contains_key(&addr)
    }

    #[must_use]
    pub fn is_current(&self, source: PeerSource) -> bool {
        self.entries
            .read()
            .get(&PeerRemote::from(source))
            .is_some_and(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
    }

    #[must_use]
    pub fn lease(&self, addr: impl Into<PeerRemote>) -> Option<PeerLease> {
        let addr = addr.into();
        self.entries
            .read()
            .get(&addr)
            .filter(|entry| !entry.lease.is_cancelled())
            .map(|entry| entry.lease.clone())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// INVARIANT: every returned source passes `is_current` at snapshot time.
    #[must_use]
    pub fn live_sessions(&self) -> Vec<PeerSource> {
        live_sessions_of(&self.entries.read())
    }

    /// INVARIANT: lock order is peer table, then any lock `operation` takes.
    pub(crate) fn with_live_sessions(&self, operation: impl FnOnce(&[PeerSource])) {
        let entries = self.entries.read();
        operation(&live_sessions_of(&entries));
    }

    pub(crate) fn for_each_ready_lease(
        &self,
        mut f: impl FnMut(Option<PeerEndpoint>, &PeerLease, &PeerInfo),
    ) {
        for (addr, entry) in self.entries.read().iter() {
            if entry.lease.is_cancelled() {
                continue;
            }
            if let Some(info) = &entry.info {
                f(addr.endpoint(), &entry.lease, info);
            }
        }
    }

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

    #[cfg(test)]
    #[must_use]
    pub(crate) fn info_of(&self, addr: impl Into<PeerRemote>) -> Option<PeerInfo> {
        let addr = addr.into();
        self.entries
            .read()
            .get(&addr)
            .and_then(|entry| entry.info.clone())
    }

    #[must_use]
    pub(crate) fn info_of_source(&self, source: PeerSource) -> Option<PeerInfo> {
        self.entries
            .read()
            .get(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
            .and_then(|entry| entry.info.clone())
    }

    #[must_use]
    pub fn sessions(&self) -> Vec<PeerSession> {
        let entries = self.entries.read();
        let mut sessions: Vec<PeerSession> = entries
            .iter()
            .map(|(addr, entry)| entry.session(*addr))
            .collect();
        sessions.sort_unstable_by_key(|session| session.lease.connection_id().get());
        sessions
    }

    #[must_use]
    pub(crate) fn usable_peers(&self) -> Vec<PeerSession> {
        let entries = self.entries.read();
        let mut sessions: Vec<PeerSession> = entries
            .iter()
            .filter(|(_, entry)| !entry.lease.is_cancelled() && entry.info.is_some())
            .map(|(addr, entry)| entry.session(*addr))
            .collect();
        sessions.sort_unstable_by_key(|session| session.lease.connection_id().get());
        sessions
    }

    /// INVARIANT: inbound, manual, and cancelled leases hold no automatic
    ///   slot, so none can displace an automatic dial.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn outbound_role_counts(&self) -> (usize, usize) {
        let mut counts = (0_usize, 0_usize);
        for entry in self.entries.read().values() {
            if entry.lease.is_inbound() || entry.lease.is_cancelled() || entry.lease.is_manual() {
                continue;
            }
            match entry.lease.role() {
                PeerRole::FullRelay => counts.0 += 1,
                PeerRole::BlockRelayOnly => counts.1 += 1,
            }
        }
        counts
    }

    #[must_use]
    pub fn ready_source(&self, addr: impl Into<PeerRemote>) -> Option<PeerSource> {
        let addr = addr.into();
        let entries = self.entries.read();
        let entry = entries.get(&addr)?;
        entry.info.as_ref()?;
        if entry.lease.is_cancelled() {
            return None;
        }
        Some(entry.lease.source(addr.endpoint()))
    }

    pub(crate) fn with_current(&self, source: PeerSource, operation: impl FnOnce()) -> bool {
        let entries = self.entries.read();
        if !entries
            .get(&PeerRemote::from(source))
            .is_some_and(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        {
            return false;
        }
        operation();
        true
    }

    /// Whether `source`'s connection published BIP144 witness relay: parent
    /// requests to it carry the witness flag, others do not.
    pub(crate) fn transaction_witness(&self, source: PeerSource) -> bool {
        let entries = self.entries.read();
        let Some(entry) = entries.get(&PeerRemote::from(source)) else {
            return false;
        };
        !entry.lease.is_cancelled()
            && entry.lease.is_current(source)
            && entry
                .info
                .as_ref()
                .is_some_and(|info| info.services & ServiceFlags::WITNESS.to_u64() != 0)
    }

    #[must_use]
    pub(crate) fn lease_source(&self, source: PeerSource) -> Option<PeerLease> {
        self.entries
            .read()
            .get(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
            .map(|entry| entry.lease.clone())
    }

    #[expect(clippy::result_large_err)]
    pub fn send(&self, source: PeerSource, message: crate::Message) -> Result<(), OutboundRefusal> {
        let entries = self.entries.read();
        let Some(entry) = entries
            .get(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return Err(OutboundRefusal::Closed(message));
        };
        entry.lease.send(message)
    }

    #[expect(clippy::result_large_err)]
    pub(crate) fn send_then(
        &self,
        source: PeerSource,
        message: crate::Message,
        published: impl FnOnce(),
    ) -> Result<(), OutboundRefusal> {
        let entries = self.entries.read();
        let Some(entry) = entries
            .get(&PeerRemote::from(source))
            .filter(|entry| entry.lease.is_current(source) && !entry.lease.is_cancelled())
        else {
            return Err(OutboundRefusal::Closed(message));
        };
        entry.lease.send(message)?;
        published();
        Ok(())
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn ready_peers(&self) -> Vec<PeerSource> {
        self.sessions()
            .into_iter()
            .filter(|session| !session.lease.is_cancelled())
            .filter_map(|session| {
                session
                    .info
                    .is_some()
                    .then(|| session.lease.source(session.endpoint))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
