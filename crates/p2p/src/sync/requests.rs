//! Budgeted body requests, prefix probes, and cold-front hedges.

use super::BlockSync;
use super::ExpectedApplyCache;
use super::ExpectedBlockHashes;
use super::GetdataRequestOutcome;
use super::frontier::{ColdFrontHedge, SyncFrontier};
use super::peers::FrontierPeer;
use super::telemetry::metric_count;
use crate::Message;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_chain::TipSnapshot;
use smallvec::SmallVec;
use std::net::SocketAddr;
use std::time::Instant;
use std::vec::Vec;

/// Requested blocks within this distance of the header tip ride the
/// compact-block flavor: reconstruction costs a fraction of the full-body
/// transfer exactly where blocks are freshest. Deeper requests keep the
/// witness flavor, where full-body availability dominates; the download
/// window stays hash-keyed, so either answer resolves the same pending
/// request.
const COMPACT_RELAY_NEAR_TIP_BLOCKS: u32 = 5;

impl BlockSync {
    /// Sends one estimated-2MiB common-prefix probe to each idle alternate.
    ///
    /// Every alternate receives the same earliest hashes, so the probe cannot
    /// create a unique out-of-order height hole. It runs once per deep owner.
    pub(super) fn send_prefix_probes(&self, probe_peers: &[FrontierPeer], now: Instant) {
        let Some((owner, hashes, required_height)) =
            self.frontier_state.lock().window.prefix_probe_plan()
        else {
            return;
        };
        let candidates = probe_peers.iter().filter(|selected| {
            selected.peer.addr != owner
                && u32::try_from(selected.peer.best_known_height)
                    .is_ok_and(|height| height >= required_height)
        });
        let mut successful = SmallVec::<[SocketAddr; 8]>::new();
        for selected in candidates {
            let peer_addr = selected.peer.addr;
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
                .send(selected.source, Message::GetData(inventory))
                .is_ok()
            {
                successful.push(peer_addr);
            }
        }
        if successful.is_empty() {
            return;
        }
        let block_count = hashes.len();
        self.frontier_state
            .lock()
            .window
            .confirm_prefix_probe(owner, hashes, &successful, now);
        metrics::counter!("node.sync.prefix_probe_peers")
            .increment(u64::try_from(successful.len()).unwrap_or(u64::MAX));
        tracing::info!(
            owner = %owner,
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
    fn compact_fetch_eligible(
        &self,
        request: &crate::download_window::PeerRequest,
        chain_tip: &TipSnapshot,
    ) -> bool {
        let Some((first_height, _)) = request.entries().next() else {
            return false;
        };
        chain_tip.height.saturating_sub(first_height) < COMPACT_RELAY_NEAR_TIP_BLOCKS
            && self.peer_table.compact_relay_of(request.peer_addr())
    }

    pub(super) fn send_getdata_for_pending_blocks(
        &self,
        sync_peer: crate::PeerSource,
        allow_expired_retry_from_peer: bool,
        peer_best_height: u32,
        chain_tip: &TipSnapshot,
        applied_tip: &TipSnapshot,
    ) -> GetdataRequestOutcome {
        if self
            .chain
            .chain_tip()
            .load_full()
            .as_ref()
            .is_none_or(|current| current.hash != chain_tip.hash)
            || self
                .chain
                .applied_tip()
                .load_full()
                .as_ref()
                .is_none_or(|current| current.hash != applied_tip.hash)
        {
            return GetdataRequestOutcome::default();
        }
        let now = Instant::now();
        let tree = self.chain.block_tree().read();
        let Some(request_start_height) =
            Self::first_connect_height(&tree, applied_tip.hash, chain_tip.tip_id)
        else {
            return GetdataRequestOutcome::default();
        };

        let request = self.frontier_state.lock().window.next_peer_request(
            sync_peer.addr,
            allow_expired_retry_from_peer,
            chain_tip,
            request_start_height,
            peer_best_height,
            &tree,
            now,
        );
        drop(tree);
        let Some(request) = request else {
            return GetdataRequestOutcome::default();
        };

        let compact_fetch = self.compact_fetch_eligible(&request, chain_tip);
        let (inventory, expected_hashes, is_contiguous) =
            Self::build_inventory(&request, compact_fetch, applied_tip.height);
        let count = inventory.len();
        let msg = Message::GetData(inventory);

        let tx = self.peer_table.lease_source(sync_peer);
        let Some(tx) = tx else {
            tracing::trace!(
                peer_addr = %request.peer_addr(),
                "block sync: target peer has no outbound channel (getdata skipped)"
            );
            return GetdataRequestOutcome::default();
        };
        let mut send_ok = false;
        let mut has_request_capacity = false;
        let still_current = self.peer_table.with_current(sync_peer, || {
            send_ok = tx.send(msg).is_ok();
            if send_ok {
                has_request_capacity = self
                    .frontier_state
                    .lock()
                    .window
                    .mark_requested(&request, sync_peer, now);
            }
        });
        if !still_current {
            return GetdataRequestOutcome::default();
        }
        if !send_ok {
            tracing::warn!(
                peer_addr = %request.peer_addr(),
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
                peer_addr = %request.peer_addr(),
                count,
                "block sync: requested compact blocks near tip"
            );
        }
        tracing::debug!(
            peer_addr = %request.peer_addr(),
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
    pub(super) fn send_cold_front_hedge(
        &self,
        frontier: &SyncFrontier,
        probe_peers: &[FrontierPeer],
        hedge: ColdFrontHedge,
        now: Instant,
    ) -> Option<crate::PeerSource> {
        if !self.frontier_chain_is_current(frontier) {
            return None;
        }
        let mut candidates = SmallVec::<[(crate::PeerSource, SocketAddr); 8]>::new();
        for selected in probe_peers {
            if selected.peer.addr != hedge.owner.addr
                && u32::try_from(selected.peer.best_known_height)
                    .is_ok_and(|height| height >= hedge.height)
            {
                candidates.push((selected.source, selected.peer.addr));
            }
        }
        let candidates: SmallVec<[(crate::PeerSource, SocketAddr); 8]> = {
            let state = self.frontier_state.lock();
            let window = &state.window;
            candidates
                .into_iter()
                .filter(|(_, addr)| {
                    !window.peer_has_expired_pending(*addr, now)
                        && !window.peer_in_staller_cooldown(*addr, now)
                })
                .collect()
        };
        let mut message = Message::GetData(vec![Inventory::WitnessBlock(
            bitcoin::BlockHash::from_byte_array(*hedge.hash.as_byte_array()),
        )]);
        for (source, peer_addr) in candidates {
            match self.peer_table.send(source, message) {
                Ok(()) => {
                    metrics::counter!("node.sync.cold_front_hedges").increment(1);
                    tracing::info!(
                        owner = %hedge.owner.addr,
                        hedge_peer = %peer_addr,
                        front_hash = %hedge.hash,
                        front_height = hedge.height,
                        "block sync: hedged cold-start stalled front"
                    );
                    return Some(source);
                }
                Err(unsent) => {
                    message = unsent;
                }
            }
        }
        None
    }
}
