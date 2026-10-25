//! Budgeted body requests, prefix probes, and cold-front hedges.

use super::BlockSync;
use super::GetdataRequestOutcome;
use super::SchedulerState;
use super::frontier::ChainFrontier;
use super::frontier::body_capability;
use super::peers::active_demonstrated_height;
use super::telemetry::metric_count;
use crate::Message;
use crate::connection::PeerSource;
use crate::download_window::BlockDownloadPolicy;
use crate::download_window::PeerRequest;
use crate::download_window::SyncPeer;
use crate::download_window::statically_fanout_eligible;
use crate::download_window::{peer_can_serve_height, servable_floor, serves_requested_height};
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_primitives::Hash256;
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use std::vec::Vec;

/// Requested blocks within this distance of the header tip ride the
/// compact-block flavor: reconstruction costs a fraction of the full-body
/// transfer exactly where blocks are freshest. Deeper requests keep the
/// witness flavor, where full-body availability dominates; the download
/// window stays hash-keyed, so either answer resolves the same pending
/// request.
pub(super) const COMPACT_RELAY_NEAR_TIP_BLOCKS: u32 = 5;

/// How long a connection that answered `notfound` for a body is demoted for
/// that same body: it is the last resort for the hash, and the request path
/// refuses to ask it again, until the interval passes.
///
/// The peer is not at fault for lacking a block, so nothing else changes: its
/// other requests, its conviction state, and its connection are untouched.
/// After the interval a peer that has since obtained the body is asked once
/// more; a fresh `notfound` starts the interval again.
pub(super) const BODY_UNAVAILABLE_RETRY: Duration = Duration::from_mins(1);

/// Exact connections that answered an outstanding body request with
/// `notfound`, keyed by connection identity and block hash.
///
/// PRE: `capacity` is the window's pending-block budget, the most requests
///   the scheduler keeps in flight at once.
/// POST: holds at most `capacity` records; a record older than
///   [`BODY_UNAVAILABLE_RETRY`] never refuses anything.
/// INVARIANT: records are keyed by exact [`PeerSource`], so a same-address
///   replacement never inherits its predecessor's answer, and ages come from
///   the monotonic clock the caller passes in. A lookup is one hash probe.
#[derive(Debug)]
pub(super) struct UnavailableBodies {
    capacity: usize,
    answered: hashbrown::HashMap<(PeerSource, Hash256), Instant>,
}

impl UnavailableBodies {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            answered: hashbrown::HashMap::new(),
        }
    }

    /// Records that `source` answered `notfound` for `hash` at `now`.
    ///
    /// Expired records leave first; when the table is still full the oldest
    /// record leaves, so the bound holds without refusing the newest answer.
    pub(super) fn note(&mut self, source: PeerSource, hash: Hash256, now: Instant) {
        self.answered
            .retain(|_, answered_at| Self::live(*answered_at, now));
        if self.answered.len() >= self.capacity
            && !self.answered.contains_key(&(source, hash))
            && let Some(oldest) = self
                .answered
                .iter()
                .min_by_key(|(_, answered_at)| **answered_at)
                .map(|(key, _)| *key)
        {
            self.answered.remove(&oldest);
        }
        self.answered.insert((source, hash), now);
    }

    /// Whether `source` answered `notfound` for `hash` within
    /// [`BODY_UNAVAILABLE_RETRY`] of `now`.
    pub(super) fn refuses(&self, source: PeerSource, hash: Hash256, now: Instant) -> bool {
        self.answered
            .get(&(source, hash))
            .is_some_and(|answered_at| Self::live(*answered_at, now))
    }

    /// Whether any entry of `request` names a body its owner answered
    /// `notfound` for. One hash probe per entry.
    pub(super) fn refuses_request(&self, request: &PeerRequest, now: Instant) -> bool {
        !self.answered.is_empty()
            && request
                .entries()
                .any(|(_, hash)| self.refuses(request.owner(), hash, now))
    }

    /// Forgets `source`'s answer for `hash`: it delivered the body, so the
    /// earlier `notfound` no longer describes it.
    pub(super) fn clear(&mut self, source: PeerSource, hash: Hash256) {
        self.answered.remove(&(source, hash));
    }

    /// Drops every record whose connection `owns` rejects.
    pub(super) fn retain_owned_by(&mut self, owns: impl Fn(&PeerSource) -> bool) {
        self.answered.retain(|(source, _), _| owns(source));
    }

    fn live(answered_at: Instant, now: Instant) -> bool {
        now.saturating_duration_since(answered_at) < BODY_UNAVAILABLE_RETRY
    }
}

/// The body hash a `notfound` vector answers a body request for, in any of
/// the three flavors this node requests (`MSG_BLOCK`, `MSG_WITNESS_BLOCK`,
/// `MSG_CMPCT_BLOCK`); `None` for every other vector.
fn not_found_block_hash(item: &Inventory) -> Option<Hash256> {
    match item {
        Inventory::CompactBlock(hash) => Some(Hash256::from_le_bytes(hash.as_byte_array())),
        other => crate::inv::inventory_block_hash(other),
    }
}

/// Releases the body fetch `source` owns for `hash`, if it owns one, and
/// remembers that `source` cannot serve it.
///
/// PRE: the caller holds the scheduler lock inside the peer table's
///   `with_current(source)` authority, so `source` is the live connection.
/// POST: `true` when `source` owned a window request for `hash` (released
///   through the owner-only delivery rejection, which also ends a timeout
///   observation or cold-front episode naming it and lowers the request
///   cursor) or a deferred owned-fetch mark for it (dropped); `false` and no
///   change otherwise.
/// INVARIANT: only the exact owning connection releases. A different
///   connection's `notfound`, or one for a hash nobody asked this connection
///   for, changes nothing. Nothing here blames or disconnects the owner.
fn release_unavailable_body(
    scheduler: &mut SchedulerState,
    source: PeerSource,
    hash: Hash256,
    now: Instant,
) -> bool {
    let SchedulerState {
        window,
        owned_body_fetches,
        body_unavailable,
        ..
    } = scheduler;
    let owns_window_request = window.pending_owner(&hash) == Some(source);
    let deferred = owned_body_fetches
        .iter()
        .position(|(owner, owned)| *owner == source && *owned == hash);
    if !owns_window_request && deferred.is_none() {
        return false;
    }
    if owns_window_request {
        window.reject_delivery(hash, Some(source), now);
    }
    if let Some(index) = deferred {
        owned_body_fetches.remove(index);
    }
    body_unavailable.note(source, hash, now);
    true
}

impl BlockSync {
    /// Routes the block vectors of one inbound `notfound` to the body fetch
    /// each answers.
    ///
    /// PRE: `source` is the connection that sent `items`.
    /// POST: every block vector that `source` is the exact owner of (a
    ///   foreground window request, a deferred owned fetch, or a historical
    ///   window request) releases that request without blame, and the next
    ///   tick replans it through the ordinary scheduler, which no longer
    ///   offers it to `source` until [`BODY_UNAVAILABLE_RETRY`] passes — the
    ///   one record in `SchedulerState::body_unavailable` serves all three
    ///   paths. Returns whether anything was released, so the caller can
    ///   wake the sync loop.
    /// INVARIANT: the peer table's `with_current` authority is held across
    ///   the scheduler mutation, so a stale connection or a same-address
    ///   replacement can neither release its predecessor's request nor be
    ///   remembered for it. Vectors that are not block vectors, and block
    ///   vectors nobody asked `source` for, are left to their own owners.
    pub(crate) fn block_not_found(&self, source: PeerSource, items: &[Inventory]) -> bool {
        if !items
            .iter()
            .any(|item| not_found_block_hash(item).is_some())
        {
            return false;
        }
        let now = Instant::now();
        let mut released = 0_usize;
        self.peer_table.with_current(source, || {
            // The historical window is its own request owner. Its lock is
            // released before the scheduler's is taken: the two are never
            // held together.
            let historical_released = self.release_historical_bodies(source, items, now);
            let mut scheduler = self.scheduler.lock();
            for hash in historical_released {
                scheduler.body_unavailable.note(source, hash, now);
                released += 1;
            }
            for hash in items.iter().filter_map(not_found_block_hash) {
                if release_unavailable_body(&mut scheduler, source, hash, now) {
                    released += 1;
                }
            }
        });
        if released > 0 {
            metrics::counter!("node.sync.body_not_found_releases")
                .increment(u64::try_from(released).unwrap_or(u64::MAX));
            tracing::debug!(
                peer_addr = ?source.endpoint,
                released,
                "block sync: peer answered notfound for requested blocks; released for replan"
            );
        }
        released > 0
    }

    /// Releases the historical-window requests `source` owns among the block
    /// vectors of `items`, returning the released hashes.
    ///
    /// PRE: the caller holds the peer table's `with_current(source)`
    ///   authority and no scheduler lock.
    /// POST: each block vector that `source` is the exact pending owner of in
    ///   the historical window is released through the owner-only delivery
    ///   rejection, which lowers that window's request cursor so the next
    ///   `request_historical` pass replans it; every other vector is left
    ///   alone.
    /// INVARIANT: only the exact owner releases, nothing is blamed, and the
    ///   record of the answer lives in the scheduler's one ledger, written by
    ///   the caller after this lock is released.
    fn release_historical_bodies(
        &self,
        source: PeerSource,
        items: &[Inventory],
        now: Instant,
    ) -> SmallVec<[Hash256; 8]> {
        let mut released = SmallVec::new();
        let mut historical = self.historical.lock();
        for hash in items.iter().filter_map(not_found_block_hash) {
            if historical.window.pending_owner(&hash) == Some(source) {
                historical.window.reject_delivery(hash, Some(source), now);
                released.push(hash);
            }
        }
        released
    }

    /// Sends one estimated-2MiB common-prefix probe to each idle alternate.
    ///
    /// Every alternate receives the same earliest hashes, so the probe cannot
    /// create a unique out-of-order height hole. It runs once per deep owner.
    pub(super) fn send_prefix_probes(&self, probe_peers: &[SyncPeer], now: Instant) {
        let Some((owner, hashes, required_height)) =
            self.scheduler.lock().window.prefix_probe_plan()
        else {
            return;
        };
        // An alternate that already answered `notfound` for one of the probe
        // hashes is not asked for it again before the retry interval ends.
        let unavailable: SmallVec<[PeerSource; 8]> = {
            let scheduler = self.scheduler.lock();
            probe_peers
                .iter()
                .filter(|peer| {
                    hashes
                        .iter()
                        .any(|hash| scheduler.body_unavailable.refuses(peer.source, *hash, now))
                })
                .map(|peer| peer.source)
                .collect()
        };
        let candidates = probe_peers.iter().filter(|peer| {
            peer.source != owner
                && !unavailable.contains(&peer.source)
                && u32::try_from(peer.best_known_height)
                    .is_ok_and(|height| height >= required_height)
        });
        let mut successful = SmallVec::<[PeerSource; 8]>::new();
        for peer in candidates {
            let inventory = hashes
                .iter()
                .map(|hash| {
                    Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
                        *hash.as_byte_array(),
                    ))
                })
                .collect();
            if self
                .peer_table
                .send(peer.source, Message::GetData(inventory))
                .is_ok()
            {
                successful.push(peer.source);
            }
        }
        if successful.is_empty() {
            return;
        }
        let block_count = hashes.len();
        self.scheduler
            .lock()
            .window
            .confirm_prefix_probe(owner, hashes, &successful, now);
        tracing::info!(
            owner = ?owner.endpoint,
            alternates = successful.len(),
            blocks = block_count,
            "block sync: started common-prefix peer probe"
        );
    }

    /// Builds one getdata inventory entry per planned block in the chosen flavor.
    fn build_inventory(
        request: &crate::download_window::PeerRequest,
        compact_fetch: bool,
    ) -> Vec<Inventory> {
        let mut inventory = Vec::with_capacity(request.len());
        for (_, hash) in request.entries() {
            let block_hash = bitcoin::BlockHash::from_byte_array(*hash.as_byte_array());
            inventory.push(if compact_fetch {
                Inventory::CompactBlock(block_hash)
            } else {
                Inventory::WitnessBlock(block_hash)
            });
        }
        inventory
    }

    /// Compact flavor is worth its reconstruction round trip only when the
    /// peer announced BIP152 relay and the whole batch sits within the
    /// near-tip window of the header tip.
    fn compact_fetch_eligible(
        &self,
        request: &crate::download_window::PeerRequest,
        frontier: &ChainFrontier,
    ) -> bool {
        let Some(chain_tip) = frontier.chain_tip.as_ref() else {
            return false;
        };
        let Some((first_height, _)) = request.entries().next() else {
            return false;
        };
        chain_tip.height.saturating_sub(first_height) < COMPACT_RELAY_NEAR_TIP_BLOCKS
            && request
                .owner()
                .endpoint
                .is_some_and(|endpoint| self.peer_table.compact_relay_of(endpoint))
    }

    /// Requests the next window batch from `source`, a usable peer from the
    /// frontier snapshot. The request start is the canonical next-required
    /// height — recovery and scheduling never disagree about the frontier.
    pub(super) fn send_getdata_for_pending_blocks(
        &self,
        source: PeerSource,
        allow_expired_retry_from_peer: bool,
        peer_best_height: u32,
        frontier: &ChainFrontier,
    ) -> GetdataRequestOutcome {
        let now = Instant::now();
        let (Some(chain_tip), Some(applied_tip), Some(required)) = (
            frontier.chain_tip.as_ref(),
            frontier.applied_tip.as_ref(),
            frontier.next_required,
        ) else {
            return GetdataRequestOutcome::default();
        };

        // The service clause that gates tick-time selection applies here
        // too: header-drain fetches and stripe retries reach this function
        // without passing the selector, so the gate is enforced at the one
        // path every body request takes (net_processing.cpp:6521-6525).
        let Some(info) = source
            .endpoint
            .and_then(|endpoint| self.peer_table.info_of(endpoint))
        else {
            return GetdataRequestOutcome::default();
        };
        let policy = BlockDownloadPolicy {
            ibd: Arc::clone(&self.ibd),
            network: self.chain.network(),
            requested_height: required.height,
        };
        if !serves_requested_height(&info, &policy) {
            return GetdataRequestOutcome::default();
        }
        let servable_floor = servable_floor(&info, &policy);
        let tree = self.chain.block_tree();
        // A plan that names a body `source` already answered `notfound` for
        // is dropped whole: nothing was marked, so the ordinary scheduler
        // plans the same blocks again, for the next peer this tick or for
        // `source` once the retry interval has passed. Nothing waits on the
        // refused peer and no message goes out, so a peer that lacks a body
        // is never polled for it at wake-up pace.
        let request = {
            let mut scheduler = self.scheduler.lock();
            let SchedulerState {
                window,
                stager,
                body_unavailable,
                ..
            } = &mut *scheduler;
            window
                .next_peer_request(
                    stager,
                    source,
                    allow_expired_retry_from_peer,
                    chain_tip,
                    required.height,
                    peer_best_height,
                    servable_floor,
                    &tree,
                    now,
                )
                .filter(|request| !body_unavailable.refuses_request(request, now))
        };
        drop(tree);
        let Some(request) = request else {
            return GetdataRequestOutcome::default();
        };

        let compact_fetch = self.compact_fetch_eligible(&request, frontier);
        let inventory = Self::build_inventory(&request, compact_fetch);
        let count = inventory.len();
        let msg = Message::GetData(inventory);

        // `send_then` holds the connection's identity through the enqueue
        // and the pending stamp under one table authority, so a replacement
        // can never be blamed for — or credited with — this request.
        let mut has_request_capacity = false;
        let sent = self.peer_table.send_then(source, msg, || {
            let mut scheduler = self.scheduler.lock();
            let SchedulerState { window, stager, .. } = &mut *scheduler;
            has_request_capacity = window.mark_requested(stager, &request, source, now);
        });
        if let Err(refusal) = sent {
            // Nothing was queued and nothing was marked, so a refusal by the
            // node's aggregate budget costs this tick only: the next tick
            // plans the request again from the window's then-current state.
            if refusal.is_saturated() {
                tracing::debug!(
                    peer_addr = ?source.endpoint,
                    "block sync: getdata deferred; node outbound budget is full"
                );
            } else {
                tracing::warn!(
                    peer_addr = ?source.endpoint,
                    "block sync: outbound channel disconnected (getdata)"
                );
            }
            return GetdataRequestOutcome::default();
        }
        metrics::histogram!("node.sync.getdata_batch_size").record(metric_count(count));
        if compact_fetch {
            tracing::info!(
                peer_addr = ?source.endpoint,
                count,
                "block sync: requested compact blocks near tip"
            );
        }
        tracing::debug!(
            peer_addr = ?source.endpoint,
            count,
            compact = compact_fetch,
            applied_height = applied_tip.height,
            chain_height = chain_tip.height,
            "block sync: sent getdata batch"
        );
        GetdataRequestOutcome {
            sent: true,
            has_request_capacity,
        }
    }

    /// Sends one untracked duplicate request for a cold-start stalled front.
    ///
    /// The original request remains the sole pending owner. This bounded
    /// hedge therefore changes neither capacity accounting nor timeout state.
    /// Returns the alternate's source so the race can be armed.
    pub(super) fn send_cold_front_hedge(
        &self,
        owner: PeerSource,
        front_hash: Hash256,
        front_height: u32,
        now: Instant,
    ) -> Option<PeerSource> {
        let sessions = self.peer_table.usable_peers();
        let tree = self.chain.block_tree();
        let active_tip = self.chain.chain_tip()?.tip_id;
        let active_front_height = tree.active_height_of(active_tip, front_hash)?;
        let policy = BlockDownloadPolicy {
            ibd: Arc::clone(&self.ibd),
            network: self.chain.network(),
            requested_height: active_front_height,
        };
        let mut eligible = SmallVec::<[PeerSource; 8]>::new();
        for session in sessions {
            let Some(peer) = session.info else {
                continue;
            };
            let source = session.lease.source(session.endpoint);
            // One capability rule for every path that asks for a body: the
            // same `body_capability` the frontier's usable-peer view
            // precomputes, so the hedge and the scheduler can never disagree
            // about whom to ask.
            let active_height = if session.demonstrated_tips.is_empty() {
                u32::try_from(peer.best_known_height).ok()
            } else {
                active_demonstrated_height(&tree, active_tip, &session.demonstrated_tips)
            };
            let capability = body_capability(peer.best_known_height, active_height);
            if source == owner || !statically_fanout_eligible(&peer, &policy) {
                continue;
            }
            if capability
                .is_some_and(|height| peer_can_serve_height(&peer, height, active_front_height))
            {
                eligible.push(source);
            }
        }
        drop(tree);
        let candidates: SmallVec<[PeerSource; 8]> = {
            let scheduler = self.scheduler.lock();
            let window = &scheduler.window;
            eligible
                .into_iter()
                .filter(|source| {
                    !window.peer_has_expired_pending(*source, now)
                        && !window.peer_in_staller_cooldown(*source, now)
                        && !scheduler.body_unavailable.refuses(*source, front_hash, now)
                })
                .collect()
        };
        let mut message = Message::GetData(vec![Inventory::WitnessBlock(
            bitcoin::BlockHash::from_byte_array(*front_hash.as_byte_array()),
        )]);
        for source in candidates {
            match self.peer_table.send(source, message) {
                Ok(()) => {
                    tracing::info!(
                        owner = ?owner.endpoint,
                        hedge_peer = ?source.endpoint,
                        %front_hash,
                        front_height,
                        "block sync: hedged cold-start stalled front"
                    );
                    return Some(source);
                }
                Err(refusal) => {
                    message = refusal.into_message();
                }
            }
        }
        None
    }
}
