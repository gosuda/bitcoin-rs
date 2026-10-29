//! Fee-aware queued inventory, contained in the transaction policy owner.
#[cfg(test)]
use bitcoin_rs_primitives::PeerEndpoint;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::secp256k1::rand::{RngCore, SeedableRng as _};
use bitcoin_rs_mempool::MempoolGateway;
use bitcoin_rs_primitives::{Amount, Txid, Wtxid};
use hashbrown::{HashMap, HashSet};

use super::{Identity, TxPolicy};
use crate::netgroup::{NetworkClass, canonical_ip, network_class};
use crate::{Message, PeerSource, PeerTable, RelayOutcome, RelayRequest};

const MAX_PENDING_PER_PEER: usize = 5_000;
const MAX_PENDING: usize = 100_000;
const MAX_KNOWN: usize = 5_000;
const MAX_BATCH: usize = 1_000;
const INVENTORY_TARGET: usize = 70;

/// Core v31.1 net.cpp builds `m_network_key` from remote `GetNetClass` plus bound
/// address bytes and port.
///
/// Socket scope/flow and the remote address/port are not part of this identity.
/// Accepted I2P SAM streams use their ephemeral local bind endpoint, so their clocks
/// are per stream; they do not share a destination-wide inbound clock.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct InboundClockKey {
    network: NetworkClass,
    bind_ip: IpAddr,
    bind_port: u16,
}

impl InboundClockKey {
    fn new(remote: crate::PeerRemote, bind: std::net::SocketAddr) -> Self {
        Self {
            network: remote.endpoint().map_or(NetworkClass::Onion, |endpoint| {
                network_class(endpoint.address())
            }),
            bind_ip: canonical_ip(bind.ip()),
            bind_port: bind.port(),
        }
    }
}

#[derive(Debug)]
pub(super) struct RelayPeer {
    pending: HashMap<Wtxid, RelayRequest>,
    known: HashSet<Identity>,
    known_order: VecDeque<Identity>,
    fee_filter: u64,
    next_inv: Instant,
    next_filter: Instant,
    last_filter: Option<u64>,
    sent_ibd_filter: bool,
}

/// Core uses exponential clocks. A 30-second ceiling additionally bounds
/// inventory latency; the random deadline is independent of admissions.
fn next_inv(now: Instant, inbound: bool, rng: &mut impl RngCore) -> Instant {
    now + exponential(if inbound { 5 } else { 2 }, rng).min(Duration::from_secs(30))
}

fn exponential(mean_secs: u32, rng: &mut impl RngCore) -> Duration {
    let unit = (f64::from(rng.next_u32()) + 1.0) / (f64::from(u32::MAX) + 2.0);
    Duration::from_secs_f64(-unit.ln() * f64::from(mean_secs)).max(Duration::from_millis(1))
}

/// Core v31.1 `FeeFilterRounder`: 1.1-spaced buckets, two-thirds rounded downward,
/// followed by the configured min-relay floor.
///
/// Fractional buckets are intentionally truncated to integer sat/kvB, as in Core.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "positive Core fee buckets are at most ten million sat/kvB"
)]
fn rounded_filter(floor: u64, minimum: u64, rng: &mut impl RngCore) -> u64 {
    if floor == 0 {
        return minimum;
    }
    let mut lower = 0.0;
    let mut upper = 50.0;
    while upper <= 10_000_000.0
        && upper < f64::from(u32::try_from(floor.min(10_000_001)).unwrap_or(10_000_001))
    {
        lower = upper;
        upper *= 1.1;
    }
    let rounded = if upper > 10_000_000.0 || !rng.next_u32().is_multiple_of(3) {
        lower
    } else {
        upper
    };
    (rounded as u64).max(minimum)
}

impl RelayPeer {
    fn new(
        now: Instant,
        inbound: bool,
        key: Option<InboundClockKey>,
        clocks: &mut HashMap<InboundClockKey, Instant>,
        rng: &mut impl RngCore,
    ) -> Self {
        let next_inv = match key {
            Some(key) => *clocks
                .entry(key)
                .or_insert_with(|| next_inv(now, true, rng)),
            None => next_inv(now, inbound, rng),
        };
        Self {
            pending: HashMap::new(),
            known: HashSet::new(),
            known_order: VecDeque::new(),
            fee_filter: 0,
            next_inv,
            next_filter: now,
            last_filter: None,
            sent_ibd_filter: false,
        }
    }

    fn note_known(&mut self, identity: Identity) {
        if self.known.insert(identity) {
            self.known_order.push_back(identity);
            if self.known_order.len() > MAX_KNOWN {
                if let Some(old) = self.known_order.pop_front() {
                    self.known.remove(&old);
                }
            }
        }
    }

    fn filter_due(
        &mut self,
        now: Instant,
        floor: u64,
        minimum: u64,
        ibd: bool,
        rng: &mut impl RngCore,
    ) -> Option<u64> {
        if self.sent_ibd_filter && !ibd {
            self.next_filter = now;
        }
        if now < self.next_filter {
            if self.next_filter > now + Duration::from_secs(300)
                && self.last_filter.is_some_and(|last| {
                    floor < last.saturating_mul(3) / 4 || floor > last.saturating_mul(4) / 3
                })
            {
                self.next_filter = now + Duration::from_millis(u64::from(rng.next_u32()) % 300_000);
            }
            return None;
        }
        self.next_filter = now + exponential(600, rng);
        let rate = rounded_filter(floor, minimum, rng);
        self.sent_ibd_filter = ibd;
        if self.last_filter == Some(rate) {
            return None;
        }
        self.last_filter = Some(rate);
        Some(rate)
    }
}

impl PeerTable {
    /// The connection's currently received BIP133 threshold, in sat/kvB.
    #[must_use]
    pub fn transaction_fee_filter(&self, source: PeerSource) -> u64 {
        self.tx_policy
            .lock()
            .relay
            .get(&source)
            .map_or(0, |peer| peer.fee_filter)
    }

    pub(crate) fn queue_transaction_relay(
        &self,
        request: RelayRequest,
        now: Instant,
        rng: &mut impl RngCore,
    ) -> RelayOutcome {
        let sessions = self.usable_peers();
        let mut policy = self.tx_policy.lock();
        policy.forget(Identity::Txid(request.txid.0));
        policy.forget(Identity::Wtxid(request.wtxid.0));
        let mut total = policy
            .relay
            .values()
            .map(|peer| peer.pending.len())
            .sum::<usize>();
        let mut outcome = RelayOutcome::default();
        for session in sessions {
            let Some(info) = session.info else { continue };
            if !session.lease.role().relays_transactions() || !info.relay_transactions {
                continue;
            }
            outcome.attempted += 1;
            let is_inbound = session.lease.is_inbound();
            let inbound = session
                .lease
                .is_inbound()
                .then(|| InboundClockKey::new(session.addr, info.addr_bind.socket_addr()));
            let TxPolicy {
                relay, inbound_inv, ..
            } = &mut *policy;
            let peer = relay
                .entry(session.lease.source(session.endpoint))
                .or_insert_with(|| RelayPeer::new(now, is_inbound, inbound, inbound_inv, rng));
            if request.source == Some(session.lease.node_id()) {
                peer.note_known(Identity::Txid(request.txid.0));
                peer.note_known(Identity::Wtxid(request.wtxid.0));
                outcome.excluded += 1;
                continue;
            }
            let identity = if info.wtxid_relay {
                Identity::Wtxid(request.wtxid.0)
            } else {
                Identity::Txid(request.txid.0)
            };
            if peer.known.contains(&identity) {
                continue;
            }
            if let Some(current) = peer.pending.get_mut(&request.wtxid) {
                if request.sequence > current.sequence {
                    *current = request;
                }
            } else if peer.pending.len() < MAX_PENDING_PER_PEER && total < MAX_PENDING {
                peer.pending.insert(request.wtxid, request);
                total += 1;
            } else {
                outcome.saturated += 1;
            }
        }
        outcome
    }

    pub(crate) fn note_transaction_inventory(&self, source: PeerSource, items: &[Inventory]) {
        let mut identities = items
            .iter()
            .filter_map(|item| Identity::from_inventory(*item))
            .peekable();
        if identities.peek().is_none() {
            return;
        }
        let sessions = self.usable_peers();
        let Some(session) = sessions
            .iter()
            .find(|session| session.lease.is_current(source))
        else {
            return;
        };
        if !session.lease.role().relays_transactions() {
            return;
        }
        let Some(info) = &session.info else { return };
        let is_inbound = session.lease.is_inbound();
        let inbound = session
            .lease
            .is_inbound()
            .then(|| InboundClockKey::new(session.addr, info.addr_bind.socket_addr()));
        {
            let mut policy = self.tx_policy.lock();
            if let Some(peer) = policy.relay.get_mut(&source) {
                for identity in identities {
                    peer.note_known(identity);
                }
                return;
            }
        }
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::from_entropy();
        let mut policy = self.tx_policy.lock();
        let TxPolicy {
            relay, inbound_inv, ..
        } = &mut *policy;
        let peer = relay.entry(source).or_insert_with(|| {
            RelayPeer::new(Instant::now(), is_inbound, inbound, inbound_inv, &mut rng)
        });
        for identity in identities {
            peer.note_known(identity);
        }
    }

    pub(crate) fn receive_fee_filter(&self, source: PeerSource, rate: i64) {
        let Ok(rate) = u64::try_from(rate) else {
            return;
        };
        if rate > Amount::MAX_MONEY.to_sat() {
            return;
        }
        let sessions = self.usable_peers();
        let Some(session) = sessions
            .iter()
            .find(|session| session.lease.is_current(source))
        else {
            return;
        };
        if !session.lease.role().relays_transactions() {
            return;
        }
        let Some(info) = &session.info else { return };
        let is_inbound = session.lease.is_inbound();
        let inbound = session
            .lease
            .is_inbound()
            .then(|| InboundClockKey::new(session.addr, info.addr_bind.socket_addr()));
        {
            let mut policy = self.tx_policy.lock();
            if let Some(peer) = policy.relay.get_mut(&source) {
                peer.fee_filter = rate;
                return;
            }
        }
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::from_entropy();
        let mut policy = self.tx_policy.lock();
        let TxPolicy {
            relay, inbound_inv, ..
        } = &mut *policy;
        relay
            .entry(source)
            .or_insert_with(|| {
                RelayPeer::new(Instant::now(), is_inbound, inbound, inbound_inv, &mut rng)
            })
            .fee_filter = rate;
    }

    pub(crate) fn poll_transaction_relay(
        &self,
        gateway: &MempoolGateway,
        now: Instant,
        ibd: bool,
        rng: &mut impl RngCore,
    ) {
        let (floor, minimum) = {
            let pool = gateway.read();
            let minimum = pool.min_relay_fee_sat_per_kvb();
            let floor = pool.min_fee_sat_per_kvb(bitcoin_rs_primitives::unix_time_secs());
            (
                if ibd {
                    Amount::MAX_MONEY.to_sat()
                } else {
                    floor
                },
                minimum,
            )
        };
        let sessions = {
            let mut policy = self.tx_policy.lock();
            let sessions = self.usable_peers();
            let live: HashSet<_> = sessions
                .iter()
                .map(|session| session.lease.source(session.endpoint))
                .collect();
            policy.relay.retain(|source, _| live.contains(source));
            sessions
        };
        for session in sessions {
            let Some(info) = session.info else { continue };
            if !session.lease.role().relays_transactions() {
                continue;
            }
            let source = session.lease.source(session.endpoint);
            let is_inbound = session.lease.is_inbound();
            let inbound = session
                .lease
                .is_inbound()
                .then(|| InboundClockKey::new(session.addr, info.addr_bind.socket_addr()));
            let requests = {
                let mut policy = self.tx_policy.lock();
                let TxPolicy {
                    relay, inbound_inv, ..
                } = &mut *policy;
                let peer = relay
                    .entry(source)
                    .or_insert_with(|| RelayPeer::new(now, is_inbound, inbound, inbound_inv, rng));
                if info.version >= 70_013 && minimum <= Amount::MAX_MONEY.to_sat() {
                    let before = (peer.last_filter, peer.sent_ibd_filter);
                    if let Some(rate) = peer.filter_due(now, floor, minimum, ibd, rng) {
                        let message = Message::FeeFilter(i64::try_from(rate).unwrap_or(i64::MAX));
                        match self.send(source, message) {
                            Ok(()) => {}
                            Err(crate::OutboundRefusal::Saturated(_)) => {
                                (peer.last_filter, peer.sent_ibd_filter) = before;
                                peer.next_filter = now;
                            }
                            Err(crate::OutboundRefusal::Closed(_)) => continue,
                        }
                    }
                }
                if now < peer.next_inv {
                    continue;
                }
                peer.next_inv = match inbound {
                    Some(key) => {
                        let shared = inbound_inv.entry(key).or_insert(now);
                        if *shared <= now {
                            *shared = next_inv(now, true, rng);
                        }
                        *shared
                    }
                    None => next_inv(now, is_inbound, rng),
                };
                if !info.relay_transactions {
                    peer.pending.clear();
                    continue;
                }
                if ibd {
                    continue;
                }
                std::mem::take(&mut peer.pending)
                    .into_values()
                    .collect::<Vec<_>>()
            };
            self.drain_relay_batch(source, info.wtxid_relay, requests, gateway);
        }
    }

    fn drain_relay_batch(
        &self,
        source: PeerSource,
        wtxid: bool,
        requests: Vec<RelayRequest>,
        gateway: &MempoolGateway,
    ) {
        if requests.is_empty() {
            return;
        }
        let target = (INVENTORY_TARGET + (requests.len() / 1000) * 5).min(MAX_BATCH);
        let candidates = {
            let pool = gateway.read();
            requests
                .into_iter()
                .filter_map(|request| {
                    let entry = pool.entry_by_txid_at_sequence(&request.txid, request.sequence)?;
                    Some(Candidate {
                        request,
                        fee_rate: entry.fee_rate,
                        fee: entry.fee,
                        vsize: entry.vsize,
                        parents: entry
                            .tx
                            .inputs
                            .iter()
                            .map(|input| input.previous_output.txid)
                            .collect(),
                    })
                })
                .collect::<Vec<_>>()
        };
        let candidates = dependency_order(candidates);
        let mut policy = self.tx_policy.lock();
        let mut total = policy
            .relay
            .values()
            .map(|peer| peer.pending.len())
            .sum::<usize>();
        let Some(peer) = policy.relay.get_mut(&source) else {
            return;
        };
        let mut items = Vec::new();
        let mut identities = Vec::new();
        let mut offered = Vec::new();
        for candidate in candidates {
            let request = candidate.request;
            let identity = if wtxid {
                Identity::Wtxid(request.wtxid.0)
            } else {
                Identity::Txid(request.txid.0)
            };
            let fee_allowed = bitcoin_rs_mempool::required_fee(peer.fee_filter, candidate.vsize)
                .is_ok_and(|required| i128::from(candidate.fee) >= required);
            if peer.known.contains(&identity) || !fee_allowed {
                continue;
            }
            if items.len() >= target {
                if peer.pending.len() < MAX_PENDING_PER_PEER
                    && total < MAX_PENDING
                    && !peer.pending.contains_key(&request.wtxid)
                {
                    peer.pending.insert(request.wtxid, request);
                    total += 1;
                }
                continue;
            }
            items.push(if wtxid {
                Inventory::WTx(bitcoin::Wtxid::from_byte_array(*request.wtxid.as_bytes()))
            } else {
                Inventory::Transaction(bitcoin::Txid::from_byte_array(*request.txid.as_bytes()))
            });
            identities.push(identity);
            offered.push(request);
        }
        if items.is_empty() {
            return;
        }
        match self.send(source, Message::Inv(items)) {
            Ok(()) => {
                for identity in identities {
                    peer.note_known(identity);
                }
            }
            Err(crate::OutboundRefusal::Saturated(_)) => {
                for request in offered {
                    if peer.pending.len() < MAX_PENDING_PER_PEER
                        && total < MAX_PENDING
                        && !peer.pending.contains_key(&request.wtxid)
                    {
                        peer.pending.insert(request.wtxid, request);
                        total += 1;
                    }
                }
            }
            Err(crate::OutboundRefusal::Closed(_)) => {
                tracing::debug!(peer_addr = ?source.endpoint, "relay inventory queue closed; connection cancelled");
            }
        }
    }
}

struct Candidate {
    request: RelayRequest,
    fee_rate: u64,
    fee: u64,
    vsize: u32,
    parents: Vec<Txid>,
}

fn dependency_order(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let indices: HashMap<_, _> = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| (candidate.request.txid, index))
        .collect();
    let mut remaining = vec![0usize; candidates.len()];
    let mut children = vec![Vec::new(); candidates.len()];
    let mut ready = BinaryHeap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let parents: HashSet<_> = candidate
            .parents
            .iter()
            .filter_map(|id| indices.get(id).copied())
            .collect();
        remaining[index] = parents.len();
        for parent in parents {
            children[parent].push(index);
        }
        if remaining[index] == 0 {
            ready.push((candidate.fee_rate, Reverse(index)));
        }
    }
    let mut candidates = candidates.into_iter().map(Some).collect::<Vec<_>>();
    let mut ordered = Vec::new();
    while let Some((_, Reverse(index))) = ready.pop() {
        if let Some(candidate) = candidates[index].take() {
            ordered.push(candidate);
        }
        for child in &children[index] {
            remaining[*child] -= 1;
            if remaining[*child] == 0 {
                if let Some(candidate) = &candidates[*child] {
                    ready.push((candidate.fee_rate, Reverse(*child)));
                }
            }
        }
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{MessageReceiver, message_channel_bounded};
    use bitcoin::secp256k1::rand::{SeedableRng, rngs::StdRng};
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_mempool::{AdmissionOrigin, Mempool, MempoolEntry, MempoolLimits};
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
    };
    use std::sync::Arc;

    fn gateway() -> MempoolGateway {
        MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(
                MempoolLimits::default(),
            ))),
            None,
            ValidationEngine::Native,
            None,
        )
    }

    fn transaction(marker: u32, parent: Option<Txid>) -> Arc<Tx> {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&marker.to_le_bytes());
        Arc::new(Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(
                    parent.unwrap_or_else(|| Txid(Hash256::from_le_bytes(&bytes))),
                    0,
                ),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: Script::from_bytes(vec![0x6a, 0x04, 1, 2, 3, 4]),
            }],
            lock_time: LockTime::ZERO,
        })
    }

    fn insert(gateway: &MempoolGateway, tx: &Arc<Tx>, fee: u64) -> RelayRequest {
        let result = gateway.insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::clone(tx), 100, fee, 1, 0, 0),
        );
        let sequence = match result {
            Ok(result) => result.sequence_of(0).unwrap_or(0),
            Err(error) => panic!("fixture admission: {error}"),
        };
        RelayRequest::new(tx.txid(), tx.wtxid(), None, sequence)
    }

    fn connect(
        table: &PeerTable,
        port: u16,
        inbound: bool,
        wtxid: bool,
        role: crate::PeerRole,
        ready: bool,
    ) -> (PeerSource, MessageReceiver) {
        let addr: crate::PeerEndpoint = ([127, 0, 0, 1], port).into();
        connect_at(table, addr, addr, inbound, wtxid, role, ready)
    }

    fn connect_at(
        table: &PeerTable,
        addr: PeerEndpoint,
        bind: PeerEndpoint,
        inbound: bool,
        wtxid: bool,
        role: crate::PeerRole,
        ready: bool,
    ) -> (PeerSource, MessageReceiver) {
        let (sender, receiver) = message_channel_bounded(1024);
        let lease = if role == crate::PeerRole::BlockRelayOnly {
            crate::PeerLease::new_block_relay(sender)
        } else if inbound {
            crate::PeerLease::new_inbound(sender)
        } else {
            crate::PeerLease::new(sender)
        };
        let source = lease.source(Some(addr));
        table.register(addr, lease.clone());
        if ready {
            let version = crate::handshake::version_message(
                1,
                0,
                crate::PeerRole::FullRelay,
                bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
            );
            let mut info = crate::PeerInfo::outbound_from_version(
                addr,
                bind.socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
                &version,
                0,
                0,
                Arc::new(crate::PeerCounters::default()),
            );
            info.wtxid_relay = wtxid;
            table.publish_info(addr, &lease, info);
        }
        (source, receiver)
    }

    fn inventory(receiver: &MessageReceiver) -> Vec<Inventory> {
        receiver
            .try_iter()
            .filter_map(|message| match message {
                Message::Inv(items) => Some(items),
                _ => None,
            })
            .flatten()
            .collect()
    }

    struct CountingRng {
        inner: bitcoin::secp256k1::rand::rngs::mock::StepRng,
        draws: usize,
    }

    impl CountingRng {
        fn new() -> Self {
            Self {
                inner: bitcoin::secp256k1::rand::rngs::mock::StepRng::new(1 << 31, 1 << 24),
                draws: 0,
            }
        }
    }

    impl RngCore for CountingRng {
        fn next_u32(&mut self) -> u32 {
            self.draws += 1;
            self.inner.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.draws += 1;
            self.inner.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.draws += 1;
            self.inner.fill_bytes(dest);
        }

        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), bitcoin::secp256k1::rand::Error> {
            self.draws += 1;
            self.inner.try_fill_bytes(dest)
        }
    }

    fn clock_peer(
        table: &PeerTable,
        remote: &str,
        bind: &str,
        inbound: bool,
    ) -> Result<(PeerSource, MessageReceiver), Box<dyn std::error::Error>> {
        let connected = connect_at(
            table,
            remote
                .parse()
                .map_err(|error| std::io::Error::other(format!("remote fixture: {error}")))?,
            bind.parse()
                .map_err(|error| std::io::Error::other(format!("bind fixture: {error}")))?,
            inbound,
            false,
            crate::PeerRole::FullRelay,
            true,
        );
        let source = connected.0;
        let endpoint = source
            .endpoint
            .ok_or_else(|| std::io::Error::other("clock fixture endpoint"))?;
        let lease = table
            .lease(endpoint)
            .ok_or_else(|| std::io::Error::other("clock fixture lease"))?;
        let mut info = table
            .info_of(endpoint)
            .ok_or_else(|| std::io::Error::other("clock fixture info"))?;
        info.version = 70_012;
        table.publish_info(endpoint, &lease, info);
        Ok(connected)
    }

    fn clock(table: &PeerTable, source: PeerSource) -> Instant {
        table.tx_policy.lock().relay[&source].next_inv
    }

    #[test]
    fn nontransaction_inventory_does_not_create_relay_state_or_clocks()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = PeerTable::new();
        let (source, _) = clock_peer(&table, "8.8.8.8:1000", "10.0.0.1:8333", true)?;
        table.note_transaction_inventory(source, &[]);
        table.note_transaction_inventory(
            source,
            &[Inventory::Block(bitcoin::BlockHash::from_byte_array(
                [1; 32],
            ))],
        );
        let policy = table.tx_policy.lock();
        assert!(policy.relay.is_empty());
        assert!(policy.inbound_inv.is_empty());
        Ok(())
    }

    #[test]
    fn inbound_clock_key_uses_network_class_and_canonical_bind_endpoint() {
        let key = |remote: &str, bind: &str| {
            InboundClockKey::new(
                remote.parse::<crate::PeerAddress>().map_or_else(
                    |error| panic!("remote: {error}"),
                    |address| crate::PeerEndpoint::new(address, 0).into(),
                ),
                bind.parse().unwrap_or_else(|error| panic!("bind: {error}")),
            )
        };
        let ipv4 = key("8.8.8.8", "10.0.0.1:8333");
        for remote in ["9.9.9.9", "::ffff:8.8.8.8", "64:ff9b::808:808"] {
            assert_eq!(ipv4, key(remote, "[::ffff:10.0.0.1]:8333"));
        }
        assert_ne!(ipv4, key("2001:4860:4860::8888", "10.0.0.1:8333"));
        assert_ne!(ipv4, key("127.0.0.1", "10.0.0.1:8333"));
        assert_ne!(ipv4, key("8.8.8.8", "10.0.0.2:8333"));
        assert_ne!(ipv4, key("8.8.8.8", "10.0.0.1:18333"));
        let plain: std::net::Ipv6Addr = "fe80::1"
            .parse()
            .unwrap_or_else(|error| panic!("IPv6: {error}"));
        let bind = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(plain, 8333, 123, 456));
        assert_eq!(
            key("8.8.8.8", "[fe80::1]:8333"),
            InboundClockKey::new(crate::PeerRemote::from(([8, 8, 8, 8], 0)), bind),
        );
    }

    #[test]
    fn inbound_peers_share_cycles_without_suppressing_due_siblings()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = CountingRng::new();
        let (a, a_rx) = clock_peer(&table, "8.8.8.8:1000", "10.0.0.1:8333", true)?;
        let (b, b_rx) = clock_peer(&table, "9.9.9.9:2000", "10.0.0.1:8333", true)?;
        let request = insert(&gateway, &transaction(1, None), 1_000);
        table.queue_transaction_relay(request, now, &mut rng);
        assert_eq!(rng.draws, 1, "one initial draw for the shared key");
        let due = clock(&table, a);
        assert_eq!(due, clock(&table, b));
        table.poll_transaction_relay(&gateway, now, false, &mut rng);
        assert!(inventory(&a_rx).is_empty() && inventory(&b_rx).is_empty());
        let (c, c_rx) = clock_peer(&table, "1.1.1.1:3000", "10.0.0.1:8333", true)?;
        let draws = rng.draws;
        table.queue_transaction_relay(request, due, &mut rng);
        assert_eq!(rng.draws, draws);
        assert_eq!(clock(&table, c), due);
        table.poll_transaction_relay(&gateway, due, false, &mut rng);
        assert_eq!(
            rng.draws,
            draws + 1,
            "one next-cycle draw, not one per peer"
        );
        for receiver in [&a_rx, &b_rx, &c_rx] {
            assert_eq!(inventory(receiver).len(), 1);
        }
        let next = clock(&table, a);
        assert!(next > due);
        assert_eq!(next, clock(&table, b));
        assert_eq!(next, clock(&table, c));
        table.poll_transaction_relay(&gateway, due, false, &mut rng);
        assert_eq!(rng.draws, draws + 1);
        for receiver in [&a_rx, &b_rx, &c_rx] {
            assert_eq!(inventory(receiver), Vec::<Inventory>::new());
        }
        Ok(())
    }

    #[test]
    fn inbound_future_clock_survives_all_creation_paths_and_reconnects()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = CountingRng::new();
        let (a, a_rx) = clock_peer(&table, "8.8.8.8:1000", "10.0.0.1:8333", true)?;
        let request = insert(&gateway, &transaction(1, None), 1_000);
        table.queue_transaction_relay(request, now, &mut rng);
        let due = clock(&table, a);
        let (b, _) = clock_peer(&table, "9.9.9.9:2000", "10.0.0.1:8333", true)?;
        table.receive_fee_filter(b, 1_000);
        let (c, _) = clock_peer(&table, "1.1.1.1:3000", "10.0.0.1:8333", true)?;
        table.note_transaction_inventory(
            c,
            &[Inventory::Transaction(bitcoin::Txid::from_byte_array(
                *request.txid.as_bytes(),
            ))],
        );
        let (d, _) = clock_peer(&table, "8.8.4.4:4000", "10.0.0.1:8333", true)?;
        table.poll_transaction_relay(&gateway, now, false, &mut rng);
        for source in [a, b, c, d] {
            assert_eq!(clock(&table, source), due);
        }
        let draws = rng.draws;
        table.queue_transaction_relay(request, now, &mut rng);
        assert_eq!(rng.draws, draws, "admission leaves the shared clock alone");
        assert!(table.disconnect_source(a));
        table.poll_transaction_relay(&gateway, now, false, &mut rng);
        assert_eq!(
            clock(&table, b),
            due,
            "disconnecting a sibling preserves the clock"
        );
        for source in [b, c, d] {
            assert!(table.disconnect_source(source));
        }
        table.poll_transaction_relay(&gateway, now, false, &mut rng);
        assert!(table.tx_policy.lock().relay.is_empty());
        let (replacement, rx) = clock_peer(&table, "8.8.8.8:1000", "10.0.0.1:8333", true)?;
        table.queue_transaction_relay(request, now, &mut rng);
        assert_ne!(a, replacement);
        assert_eq!(clock(&table, replacement), due);
        assert_eq!(
            rng.draws, draws,
            "reconnecting does not redraw a live clock"
        );
        assert_eq!(table.tx_policy.lock().inbound_inv.len(), 1);
        table.poll_transaction_relay(&gateway, due, false, &mut rng);
        assert_eq!(inventory(&rx).len(), 1);
        assert!(
            inventory(&a_rx).is_empty(),
            "old lease never receives inventory"
        );
        Ok(())
    }

    #[test]
    fn empty_inbound_ticks_advance_the_shared_clock_without_admissions()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = CountingRng::new();
        let (a, a_rx) = clock_peer(&table, "8.8.8.8:1000", "10.0.0.1:8333", true)?;
        let (b, b_rx) = clock_peer(&table, "9.9.9.9:2000", "10.0.0.1:8333", true)?;
        table.poll_transaction_relay(&gateway, now, false, &mut rng);
        let due = clock(&table, a);
        let draws = rng.draws;
        table.poll_transaction_relay(&gateway, due, false, &mut rng);
        assert_eq!(rng.draws, draws + 1);
        let next = clock(&table, a);
        assert!(next > due);
        assert_eq!(next, clock(&table, b));
        let request = insert(&gateway, &transaction(1, None), 1_000);
        table.queue_transaction_relay(request, due, &mut rng);
        table.poll_transaction_relay(&gateway, due, false, &mut rng);
        assert_eq!(rng.draws, draws + 1);
        assert!(inventory(&a_rx).is_empty() && inventory(&b_rx).is_empty());
        table.poll_transaction_relay(&gateway, next, false, &mut rng);
        assert_eq!(inventory(&a_rx).len(), 1);
        assert_eq!(inventory(&b_rx).len(), 1);
        Ok(())
    }

    #[test]
    fn different_inbound_keys_and_outbound_peers_sample_independently()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = CountingRng::new();
        let mut sources = Vec::new();
        for (remote, bind, inbound) in [
            ("8.8.8.8:1000", "10.0.0.1:8333", true),
            ("9.9.9.9:2000", "10.0.0.1:8333", true),
            ("[2001:4860:4860::8888]:3000", "10.0.0.1:8333", true),
            ("127.0.0.1:4000", "10.0.0.1:8333", true),
            ("8.8.4.4:5000", "10.0.0.2:8333", true),
            ("1.1.1.1:6000", "10.0.0.1:18333", true),
            ("8.8.8.8:7000", "10.0.0.1:8333", false),
            ("8.8.8.8:8000", "10.0.0.1:8333", false),
        ] {
            sources.push(clock_peer(&table, remote, bind, inbound)?.0);
        }
        let request = insert(&gateway, &transaction(1, None), 1_000);
        table.queue_transaction_relay(request, now, &mut rng);
        assert_eq!(table.tx_policy.lock().inbound_inv.len(), 5);
        assert_eq!(rng.draws, 7, "five inbound keys plus two outbound clocks");
        assert_eq!(clock(&table, sources[0]), clock(&table, sources[1]));
        let deadlines = sources
            .iter()
            .map(|source| clock(&table, *source))
            .collect::<HashSet<_>>();
        assert_eq!(
            deadlines.len(),
            7,
            "distinct controlled draws remain independent"
        );
        Ok(())
    }

    #[test]
    fn relay_is_delayed_excludes_source_and_preserves_negotiated_identity() {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(1);
        let (source, source_rx) =
            connect(&table, 1, false, false, crate::PeerRole::FullRelay, true);
        let (_, legacy_rx) = connect(&table, 2, true, false, crate::PeerRole::FullRelay, true);
        let (_, witness_rx) = connect(&table, 3, false, true, crate::PeerRole::FullRelay, true);
        let (_, block_rx) = connect(
            &table,
            4,
            false,
            false,
            crate::PeerRole::BlockRelayOnly,
            true,
        );
        let (_, handshake_rx) = connect(&table, 5, false, false, crate::PeerRole::FullRelay, false);
        let tx = transaction(1, None);
        let mut request = insert(&gateway, &tx, 10_000);
        request.source = Some(source.connection_id().get());
        let outcome = table.queue_transaction_relay(request, now, &mut rng);
        assert_eq!((outcome.attempted, outcome.excluded), (3, 1));
        assert!(legacy_rx.is_empty() && witness_rx.is_empty());
        table.poll_transaction_relay(&gateway, now, false, &mut rng);
        assert_eq!(inventory(&legacy_rx), []);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(31), false, &mut rng);
        assert_eq!(
            inventory(&legacy_rx),
            vec![Inventory::Transaction(bitcoin::Txid::from_byte_array(
                *request.txid.as_bytes()
            ))]
        );
        assert_eq!(
            inventory(&witness_rx),
            vec![Inventory::WTx(bitcoin::Wtxid::from_byte_array(
                *request.wtxid.as_bytes()
            ))]
        );
        assert_eq!(inventory(&source_rx), []);
        assert!(block_rx.is_empty());
        assert!(handshake_rx.is_empty());
        table.queue_transaction_relay(request, now + Duration::from_secs(31), &mut rng);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(62), false, &mut rng);
        assert!(inventory(&legacy_rx).is_empty() && inventory(&witness_rx).is_empty());
        let (_, replacement_rx) = connect(&table, 2, false, true, crate::PeerRole::FullRelay, true);
        table.queue_transaction_relay(request, now + Duration::from_secs(62), &mut rng);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(93), false, &mut rng);
        assert_eq!(
            inventory(&replacement_rx).len(),
            1,
            "replacement has its own known inventory"
        );
    }

    fn connect_on(
        table: &PeerTable,
        port: u16,
        aggregate: &Arc<crate::connection::SharedOutboundBudget>,
    ) -> (PeerSource, MessageReceiver) {
        let addr: crate::PeerEndpoint = ([127, 0, 0, 1], port).into();
        let (sender, receiver) = message_channel_bounded(1024);
        let lease = crate::PeerLease::new(sender).with_shared_budget(aggregate);
        let source = lease.source(Some(addr));
        table.register(addr, lease.clone());
        let version = crate::handshake::version_message(
            1,
            0,
            crate::PeerRole::FullRelay,
            bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
        );
        let mut info = crate::PeerInfo::outbound_from_version(
            addr,
            addr.socket_addr()
                .unwrap_or_else(|| panic!("expected IP fixture")),
            &version,
            0,
            0,
            Arc::new(crate::PeerCounters::default()),
        );
        info.wtxid_relay = true;
        table.publish_info(addr, &lease, info);
        (source, receiver)
    }

    fn fee_filters(receiver: &MessageReceiver) -> Vec<i64> {
        receiver
            .try_iter()
            .filter_map(|message| match message {
                Message::FeeFilter(rate) => Some(rate),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn feefilter_saturated_restores() {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(21);
        let aggregate = Arc::new(crate::connection::SharedOutboundBudget::with_limits(256, 0));
        let (source, rx) = connect_on(&table, 1, &aggregate);
        let state = |table: &PeerTable| {
            let policy = table.tx_policy.lock();
            let peer = &policy.relay[&source];
            (peer.last_filter, peer.sent_ibd_filter, peer.next_filter)
        };

        table.poll_transaction_relay(&gateway, now, true, &mut rng);
        let syncing = fee_filters(&rx);
        assert_eq!(syncing.len(), 1);
        let (sent_rate, sent_while_syncing, _) = state(&table);
        assert!(sent_while_syncing && sent_rate.is_some());

        let hold = crate::test_support::hog(&aggregate, 256);
        let refused_at = now + Duration::from_secs(1);
        table.poll_transaction_relay(&gateway, refused_at, false, &mut rng);
        assert!(rx.is_empty());
        let (rate, while_syncing, next) = state(&table);
        assert_eq!(rate, sent_rate, "the last sent rate is what the peer holds");
        assert!(while_syncing, "the peer still holds a syncing filter");
        assert_eq!(next, refused_at, "the filter is due again at once");

        drop(hold);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(2), false, &mut rng);
        let offered = fee_filters(&rx);
        assert_eq!(offered.len(), 1, "the refused filter is offered again");
        assert_ne!(offered, syncing, "it is the synced node's filter");
        assert!(!state(&table).1);
    }

    #[test]
    fn relay_inv_saturated_requeues() {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(22);
        let aggregate = Arc::new(crate::connection::SharedOutboundBudget::with_limits(512, 0));
        let (source, rx) = connect_on(&table, 1, &aggregate);
        let request = insert(&gateway, &transaction(1, None), 10_000);
        let identity = Identity::Wtxid(request.wtxid.0);
        table.queue_transaction_relay(request, now, &mut rng);

        let hold = crate::test_support::hog(&aggregate, 512);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(31), false, &mut rng);
        assert_eq!(inventory(&rx), Vec::new());
        {
            let policy = table.tx_policy.lock();
            let peer = &policy.relay[&source];
            assert_eq!(
                peer.pending.len(),
                1,
                "the refused request is pending again"
            );
            assert!(!peer.known.contains(&identity), "nothing was announced");
        }

        drop(hold);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(62), false, &mut rng);
        assert_eq!(
            inventory(&rx),
            vec![Inventory::WTx(bitcoin::Wtxid::from_byte_array(
                *request.wtxid.as_bytes()
            ))]
        );
        let policy = table.tx_policy.lock();
        let peer = &policy.relay[&source];
        assert!(peer.pending.is_empty());
        assert!(peer.known.contains(&identity));
    }

    #[test]
    fn latest_fee_filter_changes_only_that_peers_queued_relay() {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(2);
        let (filtered, filtered_rx) =
            connect(&table, 1, false, false, crate::PeerRole::FullRelay, true);
        let (_, other_rx) = connect(&table, 2, false, false, crate::PeerRole::FullRelay, true);
        let low = insert(&gateway, &transaction(1, None), 1_000);
        let high = insert(&gateway, &transaction(2, None), 3_000);
        table.queue_transaction_relay(low, now, &mut rng);
        table.queue_transaction_relay(high, now, &mut rng);
        table.receive_fee_filter(filtered, 20_000);
        table.receive_fee_filter(filtered, -1);
        table.receive_fee_filter(filtered, i64::MAX);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(31), false, &mut rng);
        assert_eq!(
            inventory(&filtered_rx),
            vec![Inventory::Transaction(bitcoin::Txid::from_byte_array(
                *high.txid.as_bytes()
            ))]
        );
        assert_eq!(inventory(&other_rx).len(), 2);
        assert_eq!(gateway.read().stats().txs, 2);
    }

    #[test]
    fn disappeared_or_readmitted_epoch_does_not_leave_stale_inventory() {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(3);
        let (_, rx) = connect(&table, 1, false, true, crate::PeerRole::FullRelay, true);
        let tx = transaction(1, None);
        let old = insert(&gateway, &tx, 1_000);
        table.queue_transaction_relay(old, now, &mut rng);
        gateway.clear(AdmissionOrigin::Block);
        let current = insert(&gateway, &tx, 1_000);
        assert_ne!(old.sequence, current.sequence);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(31), false, &mut rng);
        assert_eq!(inventory(&rx), []);
        table.queue_transaction_relay(current, now + Duration::from_secs(31), &mut rng);
        gateway.clear(AdmissionOrigin::Block);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(62), false, &mut rng);
        assert_eq!(inventory(&rx), []);
    }

    #[test]
    fn drain_orders_dependencies_then_eligible_feerates() {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(4);
        let (_, rx) = connect(&table, 1, false, false, crate::PeerRole::FullRelay, true);
        let parent = insert(&gateway, &transaction(1, None), 1_000);
        let child = insert(&gateway, &transaction(2, Some(parent.txid)), 9_000);
        let independent = insert(&gateway, &transaction(3, None), 5_000);
        for request in [child, parent, independent] {
            table.queue_transaction_relay(request, now, &mut rng);
        }
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(31), false, &mut rng);
        let expected = [independent, parent, child].map(|request| {
            Inventory::Transaction(bitcoin::Txid::from_byte_array(*request.txid.as_bytes()))
        });
        assert_eq!(inventory(&rx), expected);
    }

    #[test]
    fn relay_queue_and_known_inventory_have_explicit_bounds() {
        let table = PeerTable::new();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(5);
        for port in 1..=21 {
            connect(&table, port, false, false, crate::PeerRole::FullRelay, true);
        }
        let mut dropped = 0;
        for marker in 0u32..5_001 {
            let mut bytes = [0; 32];
            bytes[..4].copy_from_slice(&marker.to_le_bytes());
            let hash = Hash256::from_le_bytes(&bytes);
            let request = RelayRequest::new(Txid(hash), Wtxid(hash), None, u64::from(marker));
            dropped += table
                .queue_transaction_relay(request, now, &mut rng)
                .saturated;
        }
        let policy = table.tx_policy.lock();
        assert_eq!(
            policy
                .relay
                .values()
                .map(|peer| peer.pending.len())
                .sum::<usize>(),
            MAX_PENDING
        );
        assert!(
            policy
                .relay
                .values()
                .all(|peer| peer.pending.len() <= MAX_PENDING_PER_PEER)
        );
        assert!(dropped > 0);
        drop(policy);
        let mut peer = RelayPeer::new(now, false, None, &mut HashMap::new(), &mut rng);
        for marker in 0u32..5_001 {
            let mut bytes = [0; 32];
            bytes[..4].copy_from_slice(&marker.to_le_bytes());
            peer.note_known(Identity::Txid(Hash256::from_le_bytes(&bytes)));
        }
        assert_eq!(peer.known.len(), MAX_KNOWN);
        assert_eq!(peer.known_order.len(), MAX_KNOWN);
    }

    #[test]
    fn each_trickle_sends_one_bounded_batch() {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(6);
        let (_, rx) = connect(&table, 1, false, false, crate::PeerRole::FullRelay, true);
        for marker in 0..1_100 {
            let request = insert(&gateway, &transaction(marker, None), 1_000);
            table.queue_transaction_relay(request, now, &mut rng);
        }
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(31), false, &mut rng);
        assert_eq!(inventory(&rx).len(), 75);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(31), false, &mut rng);
        assert!(
            inventory(&rx).is_empty(),
            "same instant cannot drain another batch"
        );
        assert_eq!(
            table
                .tx_policy
                .lock()
                .relay
                .values()
                .map(|peer| peer.pending.len())
                .sum::<usize>(),
            1_025
        );
    }

    #[test]
    fn seeded_clocks_rounding_and_fee_refresh_are_deterministic() {
        let now = Instant::now();
        let mut inbound = StdRng::seed_from_u64(7);
        let mut outbound = inbound.clone();
        assert!(next_inv(now, true, &mut inbound) > next_inv(now, false, &mut outbound));
        let mut rng = StdRng::seed_from_u64(8);
        let values = (0..100)
            .map(|_| rounded_filter(1500, 1000, &mut rng))
            .collect::<HashSet<_>>();
        assert_eq!(
            values,
            HashSet::from([1405, 1545]),
            "Core 1.1-spaced bucket boundaries"
        );
        assert!((0..100).all(|_| rounded_filter(500, 1000, &mut rng) >= 1000));
        let mut peer = RelayPeer::new(now, false, None, &mut HashMap::new(), &mut rng);
        assert!(peer.filter_due(now, 1500, 1000, false, &mut rng).is_some());
        let scheduled = peer.next_filter;
        assert!(peer.filter_due(now, 1501, 1000, false, &mut rng).is_none());
        assert_eq!(peer.next_filter, scheduled);
        peer.next_filter = now + Duration::from_secs(1000);
        assert!(
            peer.filter_due(now, 300_000, 1000, false, &mut rng)
                .is_none()
        );
        assert!(peer.next_filter <= now + Duration::from_secs(300));
        peer.next_filter = now;
        assert!(
            peer.filter_due(now, Amount::MAX_MONEY.to_sat(), 1000, true, &mut rng)
                .is_some()
        );
        assert!(
            peer.filter_due(now, 1000, 1000, false, &mut rng).is_some(),
            "IBD exit refreshes immediately"
        );
    }
    #[test]
    fn remote_relay_optout_and_announced_inventory_suppress_only_that_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = PeerTable::new();
        let gateway = gateway();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(9);
        let (optout, optout_rx) =
            connect(&table, 1, false, false, crate::PeerRole::FullRelay, true);
        let (known, known_rx) = connect(&table, 2, false, true, crate::PeerRole::FullRelay, true);
        let (_, other_rx) = connect(&table, 3, false, true, crate::PeerRole::FullRelay, true);
        let endpoint = optout
            .endpoint
            .ok_or_else(|| std::io::Error::other("identified fixture"))?;
        let Some(lease) = table.lease(endpoint) else {
            return Err(std::io::Error::other("live fixture lease").into());
        };
        let Some(mut info) = table.info_of(endpoint) else {
            return Err(std::io::Error::other("published fixture info").into());
        };
        info.relay_transactions = false;
        table.publish_info(endpoint, &lease, info);
        let request = insert(&gateway, &transaction(1, None), 1_000);
        table.note_transaction_inventory(
            known,
            &[Inventory::WTx(bitcoin::Wtxid::from_byte_array(
                *request.wtxid.as_bytes(),
            ))],
        );
        table.queue_transaction_relay(request, now, &mut rng);
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(31), false, &mut rng);
        let optout_messages = optout_rx.try_iter().collect::<Vec<_>>();
        assert!(
            optout_messages
                .iter()
                .all(|message| !matches!(message, Message::Inv(_)))
        );
        assert!(
            optout_messages
                .iter()
                .any(|message| matches!(message, Message::FeeFilter(_))),
            "version relay=false declines our inventory, not the threshold for inventory sent to us"
        );
        assert_eq!(inventory(&known_rx), []);
        assert_eq!(inventory(&other_rx).len(), 1);
        Ok(())
    }
    #[test]
    fn fee_filter_uses_core_integer_fee_threshold_at_fractional_boundaries()
    -> Result<(), bitcoin_rs_mempool::MempoolError> {
        let table = PeerTable::new();
        let now = Instant::now();
        let mut rng = StdRng::seed_from_u64(10);
        let gateway = MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                ..MempoolLimits::default()
            }))),
            None,
            ValidationEngine::Native,
            None,
        );
        let (source, rx) = connect(&table, 1, false, false, crate::PeerRole::FullRelay, true);
        table.receive_fee_filter(source, 991);
        let mut expected = Vec::new();
        for (marker, fee) in [(1, 100), (2, 99)] {
            let tx = transaction(marker, None);
            let result = gateway.insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::clone(&tx), 101, fee, 1, 0, 0),
            )?;
            let request = RelayRequest::new(
                tx.txid(),
                tx.wtxid(),
                None,
                result.sequence_of(0).unwrap_or(0),
            );
            table.queue_transaction_relay(request, now, &mut rng);
            if fee == 100 {
                expected.push(Inventory::Transaction(bitcoin::Txid::from_byte_array(
                    *request.txid.as_bytes(),
                )));
            }
        }
        table.poll_transaction_relay(&gateway, now + Duration::from_secs(31), false, &mut rng);
        assert_eq!(
            inventory(&rx),
            expected,
            "Core GetFee(991,101) truncates to100 sat"
        );
        assert_eq!(
            bitcoin_rs_mempool::required_fee(1, 1),
            Ok(1),
            "positive rates charge at least one satoshi"
        );
        Ok(())
    }

    #[test]
    fn inbound_without_ip_key_keeps_inbound_cadence() {
        let now = Instant::now();
        let mut clocks = HashMap::new();
        let mut rng_in = StdRng::seed_from_u64(42);
        let mut rng_out = StdRng::seed_from_u64(42);
        let inbound = RelayPeer::new(now, true, None, &mut clocks, &mut rng_in);
        let outbound = RelayPeer::new(now, false, None, &mut clocks, &mut rng_out);
        assert!(
            inbound.next_inv > outbound.next_inv,
            "an inbound peer without an IP key must keep its inbound cadence, not degrade to outbound"
        );
        assert!(
            clocks.is_empty(),
            "a missing IP key shares no clock but must not create one"
        );
    }
}
