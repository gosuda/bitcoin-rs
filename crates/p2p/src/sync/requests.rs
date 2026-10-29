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
use crate::download_window::RefusalFilter;
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

/// Requested blocks within this distance of the header tip ride the compact-block
/// flavor: reconstruction costs a fraction of the full-body transfer exactly where
/// blocks are freshest.
///
/// Deeper requests keep the witness flavor, where full-body availability dominates; the
/// download window stays hash-keyed, so either answer resolves the same pending
/// request.
pub(super) const COMPACT_RELAY_NEAR_TIP_BLOCKS: u32 = 5;

/// How long a connection that answered `notfound` for a body is demoted for
/// that same body: it is the last resort for the hash, and the request path
/// refuses to ask it again, until the interval passes.
pub(super) const BODY_UNAVAILABLE_RETRY: Duration = Duration::from_mins(1);

/// Safety ceiling on retained availability records: every live record below it is kept,
/// so ledger pressure can never evict one peer's live answer to make room for
/// another's.
///
/// The bound caps memory at a few mebibytes, and evicting above it costs at most one
/// redundant round trip — never a stall — because per-entry filtering only re-asks a
/// peer it wrongly forgot.
pub(super) const MAX_UNAVAILABLE_BODY_RECORDS: usize = 65_536;

#[derive(Debug, Default)]
pub(super) struct UnavailableBodies {
    answered: hashbrown::HashMap<(PeerSource, Hash256), Instant>,
}

impl UnavailableBodies {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn note(&mut self, source: PeerSource, hash: Hash256, now: Instant) {
        self.answered
            .retain(|_, answered_at| Self::live(*answered_at, now));
        if self.answered.len() >= MAX_UNAVAILABLE_BODY_RECORDS
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

    pub(super) fn refuses(&self, source: PeerSource, hash: Hash256, now: Instant) -> bool {
        self.answered
            .get(&(source, hash))
            .is_some_and(|answered_at| Self::live(*answered_at, now))
    }

    pub(super) fn refused_hashes(&self, source: PeerSource, now: Instant) -> Vec<Hash256> {
        self.answered
            .iter()
            .filter_map(|((owner, hash), answered_at)| {
                (*owner == source && Self::live(*answered_at, now)).then_some(*hash)
            })
            .collect()
    }
    pub(super) fn clear(&mut self, source: PeerSource, hash: Hash256) {
        self.answered.remove(&(source, hash));
    }

    pub(super) fn retain_owned_by(&mut self, owns: impl Fn(&PeerSource) -> bool) {
        self.answered.retain(|(source, _), _| owns(source));
    }

    fn live(answered_at: Instant, now: Instant) -> bool {
        now.saturating_duration_since(answered_at) < BODY_UNAVAILABLE_RETRY
    }
}

fn not_found_block_hash(item: &Inventory) -> Option<Hash256> {
    match item {
        Inventory::CompactBlock(hash) => Some(Hash256::from_le_bytes(hash.as_byte_array())),
        other => crate::inv::inventory_block_hash(other),
    }
}

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
        if window.contains_pending(&hash) {
            body_unavailable.note(source, hash, now);
        }
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
            let historical_released = self.release_historical_bodies(source, items, now);
            let mut scheduler = self.scheduler.lock();
            for hash in historical_released {
                scheduler.body_unavailable.note(source, hash, now);
                released += 1;
            }
            for hash in items.iter().filter_map(not_found_block_hash) {
                let asked = scheduler.window.pending_owner(&hash) == Some(source)
                    || scheduler
                        .owned_body_fetches
                        .iter()
                        .any(|(owner, owned)| *owner == source && *owned == hash)
                    || scheduler.window.probe_offered(source, &hash)
                    || scheduler.window.hedge_offered(source, &hash);
                if !asked {
                    continue;
                }
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

    pub(super) fn send_prefix_probes(&self, probe_peers: &[SyncPeer], now: Instant) {
        let Some((owner, hashes, required_height)) =
            self.scheduler.lock().window.prefix_probe_plan()
        else {
            return;
        };
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
            && self.peer_table.compact_relay_of_source(request.owner())
    }

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

        let Some(info) = self.peer_table.info_of_source(source) else {
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
        let request = {
            let mut scheduler = self.scheduler.lock();
            let SchedulerState {
                window,
                stager,
                body_unavailable,
                ..
            } = &mut *scheduler;
            let is_refused = |hash| body_unavailable.refuses(source, hash, now);
            let mut refusals = RefusalFilter::new(&is_refused);
            window.next_peer_request(
                stager,
                source,
                allow_expired_retry_from_peer,
                chain_tip,
                required.height,
                peer_best_height,
                servable_floor,
                &tree,
                now,
                &mut refusals,
            )
        };
        drop(tree);
        let Some(request) = request else {
            return GetdataRequestOutcome::default();
        };

        let compact_fetch = self.compact_fetch_eligible(&request, frontier);
        let inventory = Self::build_inventory(&request, compact_fetch);
        let count = inventory.len();
        let msg = Message::GetData(inventory);

        let mut has_request_capacity = false;
        let sent = self.peer_table.send_then(source, msg, || {
            let mut scheduler = self.scheduler.lock();
            let SchedulerState { window, stager, .. } = &mut *scheduler;
            has_request_capacity = window.mark_requested(stager, &request, source, now);
        });
        if let Err(refusal) = sent {
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
#[cfg(test)]
mod tests {
    use super::BODY_UNAVAILABLE_RETRY;
    use super::MAX_UNAVAILABLE_BODY_RECORDS;
    use super::UnavailableBodies;
    use super::release_unavailable_body;
    use crate::connection::PeerSource;
    use crate::download_window::DownloadWindow;
    use crate::download_window::RefusalFilter;
    use bitcoin_rs_primitives::Hash256;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::time::Duration;
    use std::time::Instant;

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn test_chain() -> (
        bitcoin_rs_chain::BlockTree,
        Vec<(bitcoin_rs_chain::NodeId, bitcoin_rs_primitives::Header)>,
    ) {
        use bitcoin_rs_primitives::Header;
        let genesis = bitcoin_rs_primitives::Network::Regtest
            .genesis_block()
            .header;
        let headers: Vec<Header> = std::iter::successors(Some(genesis), |prev| {
            let height = prev.time.saturating_sub(genesis.time).saturating_add(1);
            let mut merkle = [0_u8; 32];
            merkle[..4].copy_from_slice(&height.to_le_bytes());
            Some(Header {
                prev_blockhash: prev.compute_hash(),
                merkle_root: bitcoin_rs_primitives::Hash256::from_le_bytes(&merkle),
                time: prev.time.saturating_add(1),
                ..*prev
            })
        })
        .take(32)
        .collect();
        let mut tree = bitcoin_rs_chain::BlockTree::new();
        let mut parent = None;
        let mut nodes = Vec::with_capacity(headers.len());
        for header in headers {
            let inserted = tree
                .insert_node(parent, header, bitcoin_rs_chain::NodeStatus::HeaderValid)
                .unwrap_or_else(|error| panic!("test header: {error}"));
            parent = Some(inserted);
            nodes.push((inserted, header));
        }
        (tree, nodes)
    }

    fn scheduler_with_owner_pending(
        owner: PeerSource,
    ) -> (super::super::SchedulerState, bitcoin_rs_primitives::Hash256) {
        use bitcoin_rs_chain::{ChainTxCount, ChainWork, TipSnapshot};
        let budget = crate::sync::default_sync_budget(bitcoin_rs_primitives::Network::Regtest);
        let mut window = DownloadWindow::new(budget);
        let mut stager = crate::BlockStager::new(budget);
        let (tree, nodes) = test_chain();
        let (tip_id, tip_header) = nodes[10];
        let now = Instant::now();
        let chain_tip = TipSnapshot {
            tip_id,
            chain_tx_count: ChainTxCount::UNKNOWN,
            height: 10,
            chainwork: ChainWork::from(11_u64),
            hash: bitcoin_rs_primitives::Hash256::from(tip_header.compute_hash()),
        };
        let never_refused = |_: bitcoin_rs_primitives::Hash256| false;
        let mut refusals = RefusalFilter::new(&never_refused);
        let request = window
            .next_peer_request(
                &mut stager,
                owner,
                false,
                &chain_tip,
                1,
                10,
                0,
                &tree,
                now,
                &mut refusals,
            )
            .unwrap_or_else(|| panic!("window must plan the test prefix"));
        let (_, hash) = request
            .entries()
            .next()
            .unwrap_or_else(|| panic!("plan must name a body"));
        assert!(window.mark_requested(&stager, &request, owner, now));
        let scheduler = super::super::SchedulerState {
            window,
            stager,
            header_request_owner: None,
            owned_body_fetches: Vec::new(),
            body_unavailable: UnavailableBodies::new(),
            chain_sync: hashbrown::HashMap::new(),
            headers_sync: hashbrown::HashMap::new(),
            stale_tip: super::super::StaleTipState::default(),
            expected_apply_cache: None,
        };
        (scheduler, hash)
    }

    #[test]
    fn racer_notfound_is_remembered_without_releasing_the_owner() {
        let owner = PeerSource::for_test(test_addr(9001));
        let racer = PeerSource::for_test(test_addr(9002));
        let (mut scheduler, hash) = scheduler_with_owner_pending(owner);
        let now = Instant::now();

        assert!(!release_unavailable_body(&mut scheduler, racer, hash, now));
        assert!(scheduler.body_unavailable.refuses(racer, hash, now));
        assert_eq!(scheduler.window.pending_owner(&hash), Some(owner));

        let unknown = bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xab; 32]);
        assert!(!scheduler.window.contains_pending(&unknown));
        assert!(!release_unavailable_body(
            &mut scheduler,
            racer,
            unknown,
            now
        ));
        assert!(!scheduler.body_unavailable.refuses(racer, unknown, now));

        assert!(release_unavailable_body(&mut scheduler, owner, hash, now));
    }

    fn test_source(port: u16) -> PeerSource {
        PeerSource::for_test(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
    }

    fn test_hash(counter: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&counter.to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    #[test]
    fn retains_every_live_record_without_a_budget_capacity() {
        let first = test_source(9_830);
        let second = test_source(9_831);
        let base = Instant::now();
        let mut ledger = UnavailableBodies::new();

        ledger.note(first, test_hash(1), base);
        ledger.note(second, test_hash(1), base + Duration::from_secs(1));
        ledger.note(first, test_hash(2), base + Duration::from_secs(2));
        let now = base + Duration::from_secs(2);
        assert!(ledger.refuses(first, test_hash(1), now));
        assert!(ledger.refuses(second, test_hash(1), now));
        assert!(ledger.refuses(first, test_hash(2), now));
        assert!(
            !ledger.refuses(second, test_hash(2), now),
            "records are keyed by exact connection"
        );
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn safety_ceiling_evicts_oldest_live_and_stays_bounded() {
        let base = Instant::now();
        let mut ledger = UnavailableBodies::new();
        let filler = test_source(9_832);
        let newcomer = test_source(9_833);

        let ceiling = u64::try_from(MAX_UNAVAILABLE_BODY_RECORDS)
            .expect("the safety ceiling fits in a hash counter");
        for counter in 0..ceiling {
            let at = base + Duration::from_micros(counter);
            ledger.answered.insert((filler, test_hash(counter)), at);
        }
        let now = base + Duration::from_millis(100);
        ledger.note(newcomer, test_hash(u64::MAX), now);

        assert_eq!(
            ledger.answered.len(),
            MAX_UNAVAILABLE_BODY_RECORDS,
            "the ceiling bounds the ledger"
        );
        assert!(
            ledger.refuses(newcomer, test_hash(u64::MAX), now),
            "the newest answer is recorded"
        );
        assert!(
            !ledger.refuses(filler, test_hash(0), now),
            "only the oldest live record leaves at the ceiling"
        );
        assert!(ledger.refuses(filler, test_hash(1), now));
        assert!(
            ledger.refuses(
                filler,
                test_hash(1),
                base + Duration::from_micros(1)
                    + BODY_UNAVAILABLE_RETRY.saturating_sub(Duration::from_millis(1)),
            ),
            "a retained record refuses until the interval has passed"
        );
    }
}
