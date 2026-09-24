//! Budgeted body requests, prefix probes, and cold-front hedges.

use super::BlockSync;
use super::ExpectedApplyCache;
use super::ExpectedBlockHashes;
use super::GetdataRequestOutcome;
use super::SchedulerState;
use super::frontier::ChainFrontier;
use super::peers::active_demonstrated_height;
use super::telemetry::metric_count;
use crate::Message;
use crate::connection::PeerSource;
use crate::download_window::SyncPeer;
use crate::download_window::statically_fanout_eligible;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_primitives::Hash256;
use smallvec::SmallVec;
use std::time::Instant;
use std::vec::Vec;

/// Requested blocks within this distance of the header tip ride the
/// compact-block flavor: reconstruction costs a fraction of the full-body
/// transfer exactly where blocks are freshest. Deeper requests keep the
/// witness flavor, where full-body availability dominates; the download
/// window stays hash-keyed, so either answer resolves the same pending
/// request.
pub(super) const COMPACT_RELAY_NEAR_TIP_BLOCKS: u32 = 5;

impl BlockSync {
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
        let candidates = probe_peers.iter().filter(|peer| {
            peer.source != owner
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
        metrics::counter!("node.sync.prefix_probe_peers")
            .increment(u64::try_from(successful.len()).unwrap_or(u64::MAX));
        tracing::info!(
            owner = %owner.addr,
            alternates = successful.len(),
            blocks = block_count,
            "block sync: started common-prefix peer probe"
        );
    }

    /// Builds one getdata inventory entry per planned block in the chosen
    /// flavor and collects the hashes of the request's contiguous leading
    /// run starting at `applied_height + 1` for the fast-apply cache.
    fn build_inventory(
        request: &crate::download_window::PeerRequest,
        compact_fetch: bool,
        applied_height: u32,
    ) -> (Vec<Inventory>, ExpectedBlockHashes, bool) {
        let mut inventory = Vec::with_capacity(request.len());
        let mut expected_hashes = ExpectedBlockHashes::with_capacity(request.len());
        let mut expected_height = applied_height.saturating_add(1);
        let mut is_contiguous = true;
        for (height, hash) in request.entries() {
            let block_hash = bitcoin::BlockHash::from_byte_array(*hash.as_byte_array());
            inventory.push(if compact_fetch {
                Inventory::CompactBlock(block_hash)
            } else {
                Inventory::WitnessBlock(block_hash)
            });
            if is_contiguous && height == expected_height {
                expected_hashes.push(hash);
                expected_height = if let Some(next) = expected_height.checked_add(1) {
                    next
                } else {
                    is_contiguous = false;
                    expected_height
                };
            } else {
                is_contiguous = false;
            }
        }
        (inventory, expected_hashes, is_contiguous)
    }

    /// Compact flavor is worth its reconstruction round trip only when the
    /// peer announced BIP152 relay and the whole batch sits within the
    /// near-tip window of the header tip.
    pub(super) fn compact_fetch_eligible(
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
            && self.peer_table.compact_relay_of(request.owner().addr)
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

        let tree = self.chain.block_tree();
        let request = {
            let mut scheduler = self.scheduler.lock();
            let SchedulerState { window, stager, .. } = &mut *scheduler;
            window.next_peer_request(
                stager,
                source,
                allow_expired_retry_from_peer,
                chain_tip,
                required.height,
                peer_best_height,
                &tree,
                now,
            )
        };
        drop(tree);
        let Some(request) = request else {
            return GetdataRequestOutcome::default();
        };

        let compact_fetch = self.compact_fetch_eligible(&request, frontier);
        let (inventory, expected_hashes, is_contiguous) =
            Self::build_inventory(&request, compact_fetch, applied_tip.height);
        let count = inventory.len();
        let msg = Message::GetData(inventory);

        // `send_then` holds the connection's identity through the enqueue
        // and the pending stamp under one table authority, so a replacement
        // can never be blamed for — or credited with — this request.
        let mut has_request_capacity = false;
        if self
            .peer_table
            .send_then(source, msg, || {
                let mut scheduler = self.scheduler.lock();
                let SchedulerState { window, stager, .. } = &mut *scheduler;
                has_request_capacity = window.mark_requested(stager, &request, source, now);
            })
            .is_err()
        {
            tracing::warn!(
                peer_addr = %source.addr,
                "block sync: outbound channel disconnected (getdata)"
            );
            return GetdataRequestOutcome::default();
        }

        if is_contiguous {
            *self.expected_apply_cache.lock() = Some(ExpectedApplyCache {
                chain_tip_hash: chain_tip.hash,
                applied_tip_hash: applied_tip.hash,
                applied_tip_height: applied_tip.height,
                offset: 0,
                hashes: expected_hashes,
            });
        }
        metrics::histogram!("node.sync.getdata_batch_size").record(metric_count(count));
        if compact_fetch {
            tracing::info!(
                peer_addr = %source.addr,
                count,
                "block sync: requested compact blocks near tip"
            );
        }
        tracing::debug!(
            peer_addr = %source.addr,
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
        let mut eligible = SmallVec::<[PeerSource; 8]>::new();
        for session in sessions {
            let Some(peer) = session.info else {
                continue;
            };
            let source = session.lease.source(session.addr);
            // Same capability rule as `UsablePeer::capability`: the
            // handshake best-known while the peer has no branch evidence,
            // else only a tip on the current active chain counts.
            let capability = if session.demonstrated_tips.is_empty() {
                u32::try_from(peer.best_known_height).ok()
            } else {
                active_demonstrated_height(&tree, active_tip, &session.demonstrated_tips)
            };
            if source != owner
                && statically_fanout_eligible(&peer)
                && capability.is_some_and(|height| height >= active_front_height)
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
                        && !window.peer_in_staller_cooldown(source.addr, now)
                })
                .collect()
        };
        let mut message = Message::GetData(vec![Inventory::WitnessBlock(
            bitcoin::BlockHash::from_byte_array(*front_hash.as_byte_array()),
        )]);
        for source in candidates {
            match self.peer_table.send(source, message) {
                Ok(()) => {
                    metrics::counter!("node.sync.cold_front_hedges").increment(1);
                    tracing::info!(
                        owner = %owner.addr,
                        hedge_peer = %source.addr,
                        %front_hash,
                        front_height,
                        "block sync: hedged cold-start stalled front"
                    );
                    return Some(source);
                }
                Err(returned) => {
                    message = returned;
                }
            }
        }
        None
    }
}
