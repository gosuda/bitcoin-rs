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
mod tests;
