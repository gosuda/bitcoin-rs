//! Bounded delivery of pinned snapshot history beside the foreground window.

use std::time::Instant;

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;

use super::BlockSync;
use crate::block_stager::StagedBlock;
use crate::download_window::{
    BlockDownloadPolicy, DownloadWindow, SyncBudget, servable_floor, serves_requested_height,
};
use crate::{BlockStager, InboundBlock, Message};

/// Independent role, shared download policy. Unvalidated bodies stay transient;
/// only the chainstate manager can publish their durable archive receipt.
pub(super) struct HistoricalDownload {
    pub(super) window: DownloadWindow,
    pub(super) stager: BlockStager,
    budget: SyncBudget,
    next_expected: Option<Hash256>,
}

impl HistoricalDownload {
    pub(super) fn new(mut budget: SyncBudget) -> Self {
        budget.max_pending_blocks = budget.max_pending_blocks.min(32);
        budget.max_received_blocks = budget.max_received_blocks.min(32);
        budget.max_pending_bytes = budget.max_pending_bytes.min(64 * 1024 * 1024);
        budget.max_received_bytes = budget.max_received_bytes.min(64 * 1024 * 1024);
        budget.max_peer_inflight = budget.max_peer_inflight.min(16);
        budget.fanout_peer_inflight = budget.fanout_peer_inflight.min(16);
        Self {
            window: DownloadWindow::new(budget),
            stager: BlockStager::new(budget),
            budget,
            next_expected: None,
        }
    }

    fn clear(&mut self) {
        if self.next_expected.is_some() {
            *self = Self::new(self.budget);
        }
    }
}

impl BlockSync {
    pub(super) fn advance_historical(&self) {
        let _work = self.historical_work.lock();
        // Bound consensus work per pass. Each chain-owned replay is itself
        // bounded; a staged body never advances the authoritative cursor.
        for connected in 0..=8 {
            let required = match self.chain.advance_historical() {
                Ok(required) => required,
                Err(error) => {
                    tracing::error!(%error, "historical validation stopped");
                    self.historical.lock().clear();
                    return;
                }
            };
            let Some((height, hash)) = required else {
                self.historical.lock().clear();
                return;
            };
            let staged = {
                let tree = self.chain.block_tree();
                let mut historical = self.historical.lock();
                historical.next_expected = Some(hash);
                let HistoricalDownload { window, stager, .. } = &mut *historical;
                window.retire_before(stager, height, &tree, Instant::now());
                if connected == 8 {
                    None
                } else {
                    stager.drain_expected_prefix(&[hash]).pop()
                }
            };
            let Some(staged) = staged else {
                self.request_historical(height, Instant::now());
                return;
            };
            if let Err(error) = self
                .chain
                .connect_historical(&staged.block, staged.serialized)
            {
                tracing::warn!(%error, "historical validation stopped");
                self.historical.lock().clear();
                return;
            }
        }
    }

    pub(super) fn request_historical(&self, height: u32, now: Instant) {
        let Some(base_hash) = self.chain.historical_base() else {
            return;
        };
        let policy = BlockDownloadPolicy {
            ibd: self.ibd.clone(),
            network: self.chain.network(),
            requested_height: height,
        };
        // PeerTable -> historical is the ingress lock order. Snapshot all
        // peer data before holding download state, and stamp via send_then.
        let live = self
            .peer_table
            .infos()
            .into_iter()
            .filter_map(|info| {
                self.peer_table
                    .ready_source(info.addr)
                    .map(|source| (source, info))
            })
            .collect::<Vec<_>>();
        let mut peers = live
            .iter()
            .filter(|(_, info)| serves_requested_height(info, &policy))
            .collect::<Vec<_>>();
        {
            let mut historical = self.historical.lock();
            let HistoricalDownload { window, stager, .. } = &mut *historical;
            window.retain_owned_by(|owner| live.iter().any(|(source, _)| source == owner));
            for hash in stager.prune_expired(now) {
                // The next request always starts at the chain-owned frontier.
                window.requeue_for_retry(&hash, Some(height), now);
            }
            window.set_fanout_eligible_peers(peers.len(), now);
            peers.sort_by_key(|(source, _)| window.peer_has_expired_pending(*source, now));
        }
        for (source, info) in peers {
            let tree = self.chain.block_tree();
            let Some(base_id) = tree.lookup(base_hash) else {
                return;
            };
            let Ok(base) = tree.node(base_id) else {
                return;
            };
            let tip = TipSnapshot {
                tip_id: base_id,
                hash: base.hash,
                height: base.height,
                chainwork: base.chainwork,
                chain_tx_count: base.chain_tx_count,
            };
            let request = {
                let mut historical = self.historical.lock();
                let HistoricalDownload { window, stager, .. } = &mut *historical;
                // Back off corrupt deliveries even if this is our only peer.
                if window.peer_in_staller_cooldown(source.addr, now) {
                    continue;
                }
                window.next_peer_request(
                    stager,
                    *source,
                    true,
                    &tip,
                    height,
                    u32::try_from(info.best_known_height).unwrap_or(0),
                    servable_floor(info, &policy),
                    &tree,
                    now,
                )
            };
            drop(tree);
            let Some(request) = request else {
                continue;
            };
            let inventory = request
                .entries()
                .map(|(_, hash)| {
                    Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(hash.to_le_bytes()))
                })
                .collect();
            let _ = self
                .peer_table
                .send_then(*source, Message::GetData(inventory), || {
                    let mut historical = self.historical.lock();
                    let HistoricalDownload { window, stager, .. } = &mut *historical;
                    window.mark_requested(stager, &request, *source, now);
                });
        }
    }

    /// Consumes owned historical bodies; returns foreground deliveries intact.
    pub(super) fn receive_historical(&self, inbound: InboundBlock) -> Option<InboundBlock> {
        let _work = self.historical_work.lock();
        let hash = inbound.block.block_hash().0;
        let Some(source) = inbound.source else {
            return Some(inbound);
        };
        if self.historical.lock().window.pending_owner(&hash) != Some(source) {
            return Some(inbound);
        }
        if !self.peer_table.is_current(source) {
            return None;
        }
        let now = Instant::now();
        if let Err(error) = self.chain.check_body_binding(&inbound.block) {
            tracing::warn!(%error, "historical body rejected");
            let mut historical = self.historical.lock();
            historical.window.reject_delivery(hash, Some(source), now);
            historical.window.mark_peer_unresponsive(source.addr, now);
            return None;
        }
        let mut historical = self.historical.lock();
        let HistoricalDownload {
            window,
            stager,
            next_expected,
            ..
        } = &mut *historical;
        match stager.insert(
            hash,
            *next_expected,
            inbound.block,
            inbound.serialized,
            Some(source),
            now,
        ) {
            StagedBlock::Memory { bytes, dropped } => {
                window.mark_received_from(hash, bytes, Some(source), now);
                for hash in dropped {
                    window.requeue_for_retry(&hash, None, now);
                }
            }
            StagedBlock::AlreadyStaged => {
                window.release_pending(&hash, now);
            }
            StagedBlock::DroppedForRetry { hash } => {
                window.requeue_for_retry(&hash, None, now);
            }
        }
        None
    }
}
