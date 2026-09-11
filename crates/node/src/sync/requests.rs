//! Budgeted body requests, prefix probes, and cold-front hedges.

use super::BlockSync;
use super::ExpectedApplyCache;
use super::ExpectedBlockHashes;
use super::GetdataRequestOutcome;
use super::peers::body_capability_height;
use super::telemetry::metric_count;
use alloc::vec::Vec;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_p2p::Message;
use bitcoin_rs_p2p::download_window::SyncPeer;
use bitcoin_rs_p2p::download_window::statically_fanout_eligible;
use bitcoin_rs_primitives::Hash256;
use smallvec::SmallVec;
use std::net::SocketAddr;
use std::time::Instant;

impl BlockSync {
    /// Sends one estimated-2MiB common-prefix probe to each idle alternate.
    ///
    /// Every alternate receives the same earliest hashes, so the probe cannot
    /// create a unique out-of-order height hole. It runs once per deep owner.
    pub(super) fn send_prefix_probes(&self, probe_peers: &[SyncPeer], now: Instant) {
        let window = self.download_window.lock();
        let Some((owner, hashes, required_height)) = window.prefix_probe_plan() else {
            return;
        };
        drop(window);
        let candidates = probe_peers.iter().filter(|peer| {
            peer.addr != owner
                && u32::try_from(peer.best_known_height)
                    .is_ok_and(|height| height >= required_height)
        });
        let mut successful = SmallVec::<[SocketAddr; 8]>::new();
        for peer in candidates {
            let peer_addr = peer.addr;
            let Some(tx) = self.peer_table.lease(peer_addr) else {
                continue;
            };
            let inventory = hashes
                .iter()
                .map(|hash| {
                    Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
                        *hash.as_byte_array(),
                    ))
                })
                .collect();
            if tx.send(Message::GetData(inventory)).is_ok() {
                successful.push(peer_addr);
            }
        }
        if successful.is_empty() {
            return;
        }
        let block_count = hashes.len();
        let window = self.download_window.lock();
        window.confirm_prefix_probe(owner, hashes, &successful, now);
        metrics::counter!("node.sync.prefix_probe_peers")
            .increment(u64::try_from(successful.len()).unwrap_or(u64::MAX));
        tracing::info!(
            owner = %owner,
            alternates = successful.len(),
            blocks = block_count,
            "block sync: started common-prefix peer probe"
        );
    }

    pub(super) fn send_getdata_for_pending_blocks(
        &self,
        sync_peer_addr: SocketAddr,
        allow_expired_retry_from_peer: bool,
        peer_best_height: u32,
        chain_tip: &TipSnapshot,
        applied_tip: &TipSnapshot,
    ) -> GetdataRequestOutcome {
        let now = Instant::now();
        let tree = self.handles.block_tree.read();
        let Some(request_start_height) =
            Self::first_connect_height(&tree, applied_tip.hash, chain_tip.tip_id)
        else {
            return GetdataRequestOutcome::default();
        };

        let window = self.download_window.lock();
        let request = window.next_peer_request(
            sync_peer_addr,
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
        drop(window);

        let count = request.len();
        let mut inventory = Vec::with_capacity(count);
        let mut expected_hashes = ExpectedBlockHashes::with_capacity(count);
        let mut expected_height = applied_tip.height.saturating_add(1);
        let mut is_contiguous = true;
        for (height, hash) in request.entries() {
            inventory.push(Inventory::WitnessBlock(
                bitcoin::BlockHash::from_byte_array(*hash.as_byte_array()),
            ));
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
        let msg = Message::GetData(inventory);

        let tx = self.peer_table.lease(request.peer_addr());
        let Some(tx) = tx else {
            tracing::trace!(
                peer_addr = %request.peer_addr(),
                "block sync: target peer has no outbound channel (getdata skipped)"
            );
            return GetdataRequestOutcome::default();
        };
        let source = tx.source(request.peer_addr());
        let mut send_ok = false;
        let mut has_request_capacity = false;
        let still_current = self.peer_table.with_current(source, || {
            send_ok = tx.send(msg).is_ok();
            if send_ok {
                has_request_capacity = self.download_window.lock().mark_requested(&request, now);
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
        tracing::debug!(
            peer_addr = %request.peer_addr(),
            count,
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
        owner: SocketAddr,
        front_hash: Hash256,
        front_height: u32,
        now: Instant,
    ) -> Option<SocketAddr> {
        let sessions = self.peer_table.sessions();
        let tree = self.handles.block_tree.read();
        let active_tip = self.handles.chain_tip.load_full()?.tip_id;
        let active_front_height = tree.active_height_of(active_tip, front_hash)?;
        let mut candidates = SmallVec::<[SocketAddr; 8]>::new();
        for session in sessions {
            let Some(peer) = session.info else {
                continue;
            };
            if peer.addr != owner
                && statically_fanout_eligible(&peer)
                && body_capability_height(
                    &peer,
                    &tree,
                    Some(active_tip),
                    &session.demonstrated_tips,
                )
                .is_some_and(|height| height >= active_front_height)
            {
                candidates.push(peer.addr);
            }
        }
        drop(tree);
        let candidates: SmallVec<[SocketAddr; 8]> = {
            let window = self.download_window.lock();
            candidates
                .into_iter()
                .filter(|addr| {
                    !window.peer_has_expired_pending(*addr, now)
                        && !window.peer_in_staller_cooldown(*addr, now)
                })
                .collect()
        };
        let mut message = Message::GetData(vec![Inventory::WitnessBlock(
            bitcoin::BlockHash::from_byte_array(*front_hash.as_byte_array()),
        )]);
        for peer_addr in candidates {
            let tx = self.peer_table.lease(peer_addr);
            let Some(tx) = tx else {
                continue;
            };
            match tx.send(message) {
                Ok(()) => {
                    metrics::counter!("node.sync.cold_front_hedges").increment(1);
                    tracing::info!(
                        owner = %owner,
                        hedge_peer = %peer_addr,
                        %front_hash,
                        front_height,
                        "block sync: hedged cold-start stalled front"
                    );
                    return Some(peer_addr);
                }
                Err(error) => {
                    message = error.0;
                }
            }
        }
        None
    }
}
