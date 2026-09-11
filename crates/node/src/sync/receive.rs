//! Bounded inbound body draining and staged-body admission.

use alloc::vec::Vec;

use bitcoin_rs_chain::{BlockTree, NodeId, TipSnapshot};

use bitcoin_rs_p2p::{InboundBlock, download_window::INBOUND_BLOCK_STAGE_CHUNK};

use bitcoin_rs_primitives::Hash256;

use std::time::Instant;

use super::{BlockSync, stage::StagedBlock};

impl BlockSync {
    pub(super) fn drain_inbound_blocks(&self) {
        let mut apply_head_check = None;
        let mut next_expected_hash = None;
        let mut blocks = Vec::with_capacity(INBOUND_BLOCK_STAGE_CHUNK);
        let mut received = 0_usize;
        let mut receiver_empty = false;
        let saw_block = false;
        while !receiver_empty {
            receiver_empty = self.fill_inbound_block_chunk(
                &mut blocks,
                saw_block,
                &mut next_expected_hash,
                &mut apply_head_check,
            );
            if !blocks.is_empty() {
                received = received.saturating_add(
                    self.buffer_received_block_chunk(&mut blocks, next_expected_hash),
                );
            }
        }
        if received == 0 && self.block_stager.lock().received_len() == 0 {
            return;
        }

        let now = Instant::now();
        let dropped = self.block_stager.lock().prune_expired(now);
        let pruned = !dropped.is_empty();
        if pruned {
            let tree = self.handles.block_tree.read();
            let height_updates: Vec<(Hash256, u32)> = dropped
                .iter()
                .filter_map(|dropped| {
                    let node_id = tree.lookup(dropped.hash)?;
                    tree.node(node_id)
                        .ok()
                        .map(|node| (dropped.hash, node.height))
                })
                .collect();
            drop(tree);
            let mut window = self.download_window.lock();
            for (hash, height) in height_updates {
                window.update_received_height(&hash, height);
            }
            for dropped in dropped {
                window.drop_received_for_retry(&dropped.hash);
            }
        }

        self.switch_branch_if_outweighed();
        let (applied, failed) = self.apply_buffered_blocks(apply_head_check);
        if received > 0 || applied > 0 || failed > 0 {
            tracing::debug!(
                received,
                applied,
                failed,
                "block sync: drained inbound blocks"
            );
        }
        if received > 0 || pruned || applied > 0 || failed > 0 {
            self.record_sync_metrics();
        }
    }

    pub(super) fn fill_inbound_block_chunk(
        &self,
        blocks: &mut Vec<InboundBlock>,
        saw_block: bool,
        next_expected_hash: &mut Option<Hash256>,
        apply_head_check: &mut Option<Hash256>,
    ) -> bool {
        let receiver = self.inbound_blocks_rx.lock();
        while blocks.len() < INBOUND_BLOCK_STAGE_CHUNK {
            let Ok(inbound) = receiver.try_recv() else {
                return true;
            };
            if !saw_block {
                *next_expected_hash = self.next_expected_block_hash();
                *apply_head_check = next_expected_hash
                    .as_ref()
                    .copied()
                    .filter(|hash| *hash != Hash256::from(inbound.block.block_hash()));
            }
            blocks.push(inbound);
        }
        false
    }

    /// Uses the active-chain height index only while the applied tip is its prefix.
    ///
    /// During a header-first reorg the caller retains old-height blocks rather
    /// than walking the applied ancestry or dropping a body from the new branch.
    pub(super) fn indexed_applied_ancestry_tip(
        tree: &BlockTree,
        applied_tip: &TipSnapshot,
    ) -> Option<NodeId> {
        let active_tip = tree.tip()?;
        (tree.node_at_height_from(active_tip.tip_id, applied_tip.height)
            == Some(applied_tip.tip_id))
        .then_some(active_tip.tip_id)
    }

    pub(super) fn buffer_received_block_chunk(
        &self,
        blocks: &mut Vec<InboundBlock>,
        next_expected_hash: Option<Hash256>,
    ) -> usize {
        // A cold-start hedge can arrive after its original copy was applied.
        // Drop only blocks proven to lie on the applied ancestry; a known
        // side-chain block at the same or lower height must remain eligible.
        if let Some(applied_tip) = self.handles.applied_tip.load_full() {
            let tree = self.handles.block_tree.read();
            let indexed_tip = Self::indexed_applied_ancestry_tip(&tree, &applied_tip);
            blocks.retain(|inbound| {
                let hash = Hash256::from(inbound.block.block_hash());
                let Some(node_id) = tree.lookup(hash) else {
                    return true;
                };
                let Ok(node) = tree.node(node_id) else {
                    return true;
                };
                node.height > applied_tip.height
                    || indexed_tip.is_none_or(|tip_id| {
                        tree.node_at_height_from(tip_id, node.height) != Some(node_id)
                    })
            });
        }
        let mut staged_blocks = Vec::with_capacity(blocks.len());
        let now = Instant::now();
        {
            let mut stager = self.block_stager.lock();
            for inbound in blocks.drain(..) {
                let hash = Hash256::from(inbound.block.block_hash());
                let source = inbound.source;
                let staged = stager.insert(
                    hash,
                    next_expected_hash,
                    inbound.block,
                    inbound.serialized,
                    now,
                );
                staged_blocks.push((hash, source, staged));
            }
        }

        let mut retry_count = 0_u64;
        let staged_count = staged_blocks.len();
        {
            let mut window = self.download_window.lock();
            for (hash, source, staged) in staged_blocks {
                let source_peer = source
                    .filter(|source| self.peer_table.is_current(*source))
                    .map(|source| source.addr);
                match staged {
                    StagedBlock::AlreadyStaged => {
                        metrics::counter!("node.sync.duplicate_deliveries").increment(1);
                        if let Some(source_peer) = source_peer {
                            window.credit_duplicate_delivery(hash, source_peer);
                        }
                    }
                    StagedBlock::Memory { bytes, dropped } => {
                        window.mark_received_from(hash, bytes, source_peer, now);
                        for dropped in dropped {
                            window.drop_received_for_retry(&dropped.hash);
                            retry_count = retry_count.saturating_add(1);
                        }
                    }
                    StagedBlock::DroppedForRetry { dropped } => {
                        window.drop_for_retry(&dropped.hash);
                        retry_count = retry_count.saturating_add(1);
                        tracing::warn!(%hash, "block sync: received block buffer full; dropping block for retry");
                    }
                }
            }
        }
        if retry_count > 0 {
            metrics::counter!("node.sync.retry_count").increment(retry_count);
        }
        staged_count
    }
}
