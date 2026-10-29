//! Bounded inbound body draining and exact staged-body admission.

use super::BlockSync;
use super::chain::HeaderAdmission;
use super::chain::SyncChainError;
use super::peers::is_peer_fault;
use crate::InboundBlock;
use crate::block_stager::StagedBlock;
use crate::connection::PeerSource;
use crate::download_window::INBOUND_BLOCK_STAGE_CHUNK;
use crate::download_window::RejectDelivery;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN;
use smallvec::SmallVec;
use std::time::Instant;
use std::vec::Vec;

#[derive(Clone, Copy)]
enum DeliveryCredit {
    Duplicate,
    Delivery(Option<u32>),
}

const MAX_UNRESOLVED_STAGED_BODIES: usize = 64;

#[derive(Clone, Copy)]
enum BodyAdmission {
    Staged,
    Requested,
    Unrequested { gate_pending: bool },
}

impl BlockSync {
    pub(super) fn drain_inbound_blocks(&self) {
        let mut apply_head_check = None;
        let mut next_expected_hash = None;
        let mut blocks = Vec::with_capacity(INBOUND_BLOCK_STAGE_CHUNK);
        let mut received = 0_usize;
        let mut receiver_empty = false;
        let mut saw_block = false;
        while !receiver_empty {
            receiver_empty = self.fill_inbound_block_chunk(
                &mut blocks,
                &mut saw_block,
                &mut next_expected_hash,
                &mut apply_head_check,
            );
            if !blocks.is_empty() {
                received = received.saturating_add(
                    self.buffer_received_block_chunk(&mut blocks, next_expected_hash),
                );
            }
        }
        if received == 0 && self.scheduler.lock().stager.received_len() == 0 {
            return;
        }

        self.admit_staged_headers();

        let now = Instant::now();
        let dropped = self.scheduler.lock().stager.prune_expired(now);
        let pruned = !dropped.is_empty();
        if pruned {
            let requeues: Vec<(Hash256, Option<u32>)> = {
                let tree = self.chain.block_tree();
                dropped
                    .iter()
                    .map(|hash| {
                        let height = tree
                            .lookup(*hash)
                            .and_then(|node_id| tree.node(node_id).ok())
                            .map(|node| node.height);
                        (*hash, height)
                    })
                    .collect()
            };
            let mut scheduler = self.scheduler.lock();
            for (hash, height) in requeues {
                scheduler.window.requeue_for_retry(&hash, height, now);
            }
        }

        if let Some(demoted_tip) = self.switch_branch_if_outweighed() {
            self.record_demoted_tip(demoted_tip);
        }
        self.recheck_staged_gates();
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

    fn fill_inbound_block_chunk(
        &self,
        blocks: &mut Vec<InboundBlock>,
        saw_block: &mut bool,
        next_expected_hash: &mut Option<Hash256>,
        apply_head_check: &mut Option<Hash256>,
    ) -> bool {
        while blocks.len() < INBOUND_BLOCK_STAGE_CHUNK {
            let Ok(inbound) = self.inbound_blocks_rx.try_recv() else {
                return true;
            };
            if inbound
                .source
                .is_some_and(|source| !self.peer_table.is_current(source))
            {
                continue;
            }
            let Some(inbound) = self.receive_historical(inbound) else {
                continue;
            };
            if !*saw_block {
                *next_expected_hash = self.next_expected_block_hash();
                *apply_head_check = next_expected_hash
                    .as_ref()
                    .copied()
                    .filter(|hash| *hash != Hash256::from(inbound.payload().block().block_hash()));
            }
            blocks.push(inbound);
            *saw_block = true;
        }
        false
    }

    pub(super) fn indexed_applied_ancestry_tip(
        tree: &BlockTree,
        applied_tip: &TipSnapshot,
    ) -> Option<NodeId> {
        let active_tip = tree.tip()?;
        Self::is_ancestor_at_height(
            tree,
            applied_tip.tip_id,
            applied_tip.height,
            active_tip.tip_id,
        )
        .then_some(active_tip.tip_id)
    }

    fn discard_inadmissible_header_bodies(&self, invalid: &[(Hash256, Option<crate::PeerSource>)]) {
        let blamed: Vec<crate::PeerSource> = invalid
            .iter()
            .filter_map(|(_, source)| *source)
            .filter(|source| {
                if self.peer_table.disconnect_source(*source) {
                    self.clear_header_request_for(*source);
                    true
                } else {
                    false
                }
            })
            .collect();
        let mut scheduler = self.scheduler.lock();
        for (hash, _) in invalid {
            scheduler.stager.discard(hash);
        }
        for source in &blamed {
            scheduler
                .window
                .mark_peer_unresponsive(*source, Instant::now());
        }
        tracing::debug!(
            discarded = invalid.len(),
            "block sync: discarded bodies with inadmissible headers"
        );
    }

    fn admit_staged_headers(&self) {
        let unadmitted: Vec<(Hash256, Header, Option<crate::PeerSource>)> = {
            let tree = self.chain.block_tree();
            let scheduler = self.scheduler.lock();
            scheduler
                .stager
                .staged_headers()
                .filter(|(hash, _, _)| tree.lookup(*hash).is_none())
                .collect()
        };
        let mut missing_parent = false;
        let mut credit_refresh_needed = false;
        let mut invalid: Vec<(Hash256, Option<crate::PeerSource>)> = Vec::new();
        for (hash, header, source) in unadmitted {
            let Some(admission) = self.route_headers_batch(&[header], source, false, 1) else {
                continue;
            };
            match admission {
                HeaderAdmission::Accepted {
                    announced_tip: Some(tip_hash),
                    active_height,
                    demoted_tip,
                    ..
                } => {
                    self.record_admitted_tips(demoted_tip, Some(tip_hash), source);
                    if let Some(source) =
                        source.filter(|source| self.peer_table.is_current(*source))
                    {
                        self.peer_table
                            .note_announced_tip(source, tip_hash, active_height);
                        credit_refresh_needed = true;
                    }
                }
                HeaderAdmission::Rejected(
                    ChainError::MissingParent { .. } | ChainError::NoCommonAncestor { .. },
                ) => {
                    missing_parent = true;
                }
                HeaderAdmission::Rejected(error) if is_peer_fault(&error) => {
                    invalid.push((hash, source));
                }
                _ => {}
            }
        }
        if !invalid.is_empty() {
            self.discard_inadmissible_header_bodies(&invalid);
        }
        self.resolve_owned_body_fetches();
        if credit_refresh_needed {
            self.refresh_active_peer_credit();
        }
        if missing_parent {
            self.request_headers_from_eligible();
        }
    }

    fn recheck_staged_gates(&self) {
        let resolved: Vec<Hash256> = {
            let tree = self.chain.block_tree();
            let scheduler = self.scheduler.lock();
            scheduler
                .stager
                .gate_pending_hashes()
                .filter(|hash| tree.lookup(*hash).is_some())
                .collect()
        };
        if resolved.is_empty() {
            return;
        }
        let chain_tip = self.chain.chain_tip();
        let applied_tip = self.chain.applied_tip();
        let minimum_chain_work = self.chain.network().minimum_chain_work();
        let tree = self.chain.block_tree();
        let switch_pending = match (chain_tip.as_deref(), applied_tip.as_deref()) {
            (Some(tip), Some(applied)) => tree
                .lookup(applied.hash)
                .is_none_or(|id| tree.node_at_height_from(tip.tip_id, applied.height) != Some(id)),
            _ => false,
        };
        let mut scheduler = self.scheduler.lock();
        let mut discarded = 0_usize;
        for hash in resolved {
            if scheduler.window.contains_pending(&hash)
                || unrequested_body_admissible(
                    &tree,
                    hash,
                    chain_tip.as_deref(),
                    applied_tip.as_deref(),
                    minimum_chain_work,
                )
            {
                scheduler.stager.clear_gate_pending(&hash);
                continue;
            }
            let on_tip_branch = chain_tip.as_deref().is_some_and(|tip| {
                tree.lookup(hash)
                    .and_then(|id| tree.node(id).ok().map(|node| (id, node.height)))
                    .is_some_and(|(id, height)| {
                        tree.node_at_height_from(tip.tip_id, height) == Some(id)
                    })
            });
            if switch_pending && on_tip_branch {
                continue;
            }
            scheduler.stager.discard(&hash);
            discarded = discarded.saturating_add(1);
        }
        if discarded > 0 {
            tracing::debug!(
                discarded,
                "block sync: discarded staged bodies that resolved inadmissible"
            );
        }
    }

    #[expect(clippy::too_many_lines)]
    pub(super) fn buffer_received_block_chunk(
        &self,
        blocks: &mut Vec<InboundBlock>,
        next_expected_hash: Option<Hash256>,
    ) -> usize {
        if let Some(applied_tip) = self.chain.applied_tip() {
            let tree = self.chain.block_tree();
            let indexed_tip = Self::indexed_applied_ancestry_tip(&tree, &applied_tip);
            blocks.retain(|inbound| {
                let hash = Hash256::from(inbound.payload().block().block_hash());
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

        let admission_plan: Vec<BodyAdmission> = {
            let chain_tip = self.chain.chain_tip();
            let applied_tip = self.chain.applied_tip();
            let minimum_chain_work = self.chain.network().minimum_chain_work();
            let tree = self.chain.block_tree();
            let scheduler = self.scheduler.lock();
            let offered = blocks.len();
            let mut admission_plan = Vec::with_capacity(offered);
            blocks.retain(|inbound| {
                let hash = Hash256::from(inbound.payload().block().block_hash());
                if scheduler.stager.contains(&hash) {
                    admission_plan.push(BodyAdmission::Staged);
                    return true;
                }
                let requested = scheduler.window.contains_pending(&hash);
                if !requested
                    && !unrequested_body_admissible(
                        &tree,
                        hash,
                        chain_tip.as_deref(),
                        applied_tip.as_deref(),
                        minimum_chain_work,
                    )
                {
                    return false;
                }
                let header_unknown = tree.lookup(hash).is_none();
                admission_plan.push(if requested {
                    BodyAdmission::Requested
                } else {
                    BodyAdmission::Unrequested {
                        gate_pending: header_unknown,
                    }
                });
                true
            });
            let discarded = offered.saturating_sub(blocks.len());
            if discarded > 0 {
                tracing::debug!(
                    discarded,
                    "block sync: discarded unrequested bodies Core would not process"
                );
            }
            admission_plan
        };

        let binding_results: Vec<Result<(), SyncChainError>> = blocks
            .iter()
            .zip(&admission_plan)
            .map(|(inbound, admission)| {
                if matches!(admission, BodyAdmission::Staged) {
                    Ok(())
                } else {
                    self.chain.check_body_binding(inbound.payload().block())
                }
            })
            .collect();

        let mut staged_blocks = Vec::with_capacity(blocks.len());
        let mut reject_deliveries = Vec::new();
        let mut refused_at_budget = 0_usize;
        let mut refused_at_quota = 0_usize;
        let now = Instant::now();
        {
            let mut scheduler = self.scheduler.lock();
            let stager = &mut scheduler.stager;
            for (inbound, (admission, binding_result)) in blocks
                .drain(..)
                .zip(admission_plan.into_iter().zip(binding_results))
            {
                let hash = Hash256::from(inbound.payload().block().block_hash());
                let source = inbound.source;
                let _ = inbound.forward_credit;
                let payload = inbound.into_payload();
                if matches!(admission, BodyAdmission::Staged) {
                    staged_blocks.push((hash, source, StagedBlock::AlreadyStaged));
                    continue;
                }
                if let Err(error) = binding_result {
                    metrics::counter!("node.sync.body_binding_drops").increment(1);
                    let witness = payload
                        .block()
                        .txs
                        .first()
                        .and_then(|tx| tx.inputs.first())
                        .map(|input| &input.witness);
                    tracing::warn!(
                        %hash, %error, ?source,
                        serialized_bytes = payload.bytes().len(),
                        transactions = payload.block().txs.len(),
                        coinbase_witness_items = witness.map_or(0, bitcoin_rs_primitives::Witness::len),
                        coinbase_witness_first_bytes = witness.and_then(|stack| stack.first()).map_or(0, Vec::len),
                        "block sync: body/header binding failed; rejecting delivery"
                    );
                    reject_deliveries.push((hash, source));
                    continue;
                }
                if stager.contains(&hash) {
                    staged_blocks.push((hash, source, StagedBlock::AlreadyStaged));
                    continue;
                }
                if matches!(admission, BodyAdmission::Unrequested { .. })
                    && stager.count_headroom() == 0
                {
                    refused_at_budget = refused_at_budget.saturating_add(1);
                    continue;
                }
                if matches!(admission, BodyAdmission::Unrequested { gate_pending: true })
                    && stager.gate_pending_count() >= MAX_UNRESOLVED_STAGED_BODIES
                {
                    refused_at_quota = refused_at_quota.saturating_add(1);
                    continue;
                }
                let staged = stager.insert(hash, next_expected_hash, payload, source, now);
                if matches!(admission, BodyAdmission::Unrequested { gate_pending: true })
                    && matches!(staged, StagedBlock::Memory { .. })
                {
                    stager.set_gate_pending(&hash);
                }
                staged_blocks.push((hash, source, staged));
            }
        }
        if refused_at_budget > 0 {
            tracing::debug!(
                refused_at_budget,
                "block sync: refused unrequested bodies at the staging count budget"
            );
        }
        if refused_at_quota > 0 {
            tracing::debug!(
                refused_at_quota,
                "block sync: refused unresolved bodies at the gate-pending quota"
            );
        }

        for (_, source, _) in &mut staged_blocks {
            *source = source.filter(|source| self.peer_table.is_current(*source));
        }

        let staged_blocks: Vec<_> = {
            let tree = self.chain.block_tree();
            staged_blocks
                .into_iter()
                .map(|(hash, source_peer, staged)| {
                    let dropped_heights = match &staged {
                        StagedBlock::Memory { dropped, .. } => dropped
                            .iter()
                            .map(|entry| {
                                tree.lookup(*entry)
                                    .and_then(|node_id| tree.node(node_id).ok())
                                    .map(|node| node.height)
                            })
                            .collect(),
                        _ => Vec::new(),
                    };
                    (hash, source_peer, staged, dropped_heights)
                })
                .collect()
        };
        let mut retry_count = 0_u64;
        let staged_count = staged_blocks.len() + reject_deliveries.len();
        let mut delivery_credits: SmallVec<[(Hash256, PeerSource, DeliveryCredit); 8]> =
            SmallVec::new();
        {
            let mut scheduler = self.scheduler.lock();
            let window = &mut scheduler.window;
            for (hash, source_peer, staged, dropped_heights) in staged_blocks {
                match staged {
                    StagedBlock::AlreadyStaged => {
                        metrics::counter!("node.sync.duplicate_deliveries").increment(1);
                        if let Some(source_peer) = source_peer {
                            delivery_credits.push((hash, source_peer, DeliveryCredit::Duplicate));
                        }
                    }
                    StagedBlock::Memory { bytes, dropped } => {
                        let pending_height = window.mark_received_from(hash, bytes, None, now);
                        if let Some(source_peer) = source_peer {
                            delivery_credits.push((
                                hash,
                                source_peer,
                                DeliveryCredit::Delivery(pending_height),
                            ));
                        }
                        for (dropped_hash, height) in dropped.into_iter().zip(dropped_heights) {
                            window.requeue_for_retry(&dropped_hash, height, now);
                            retry_count = retry_count.saturating_add(1);
                        }
                    }
                    StagedBlock::DroppedForRetry { hash } => {
                        window.requeue_for_retry(&hash, None, now);
                        retry_count = retry_count.saturating_add(1);
                        tracing::warn!(%hash, "block sync: received block buffer full; dropping block for retry");
                    }
                }
            }
        }
        let mut credit_idx = 0;
        while credit_idx < delivery_credits.len() {
            let source_peer = delivery_credits[credit_idx].1;
            let start = credit_idx;
            while credit_idx < delivery_credits.len()
                && delivery_credits[credit_idx].1 == source_peer
            {
                credit_idx += 1;
            }
            let batch = &delivery_credits[start..credit_idx];
            self.peer_table.with_current(source_peer, || {
                let mut scheduler = self.scheduler.lock();
                for (hash, _, credit) in batch {
                    scheduler.body_unavailable.clear(source_peer, *hash);
                    match *credit {
                        DeliveryCredit::Duplicate => {
                            scheduler
                                .window
                                .credit_duplicate_delivery(*hash, source_peer);
                        }
                        DeliveryCredit::Delivery(pending_height) => {
                            scheduler.window.credit_delivery_from(
                                *hash,
                                source_peer,
                                pending_height,
                                now,
                            );
                        }
                    }
                }
            });
        }
        for (hash, source) in reject_deliveries {
            let mut rejected = RejectDelivery::DiscardedUnsolicited;
            let current = source.is_some_and(|source| {
                self.peer_table.with_current(source, || {
                    rejected =
                        self.scheduler
                            .lock()
                            .window
                            .reject_delivery(hash, Some(source), now);
                })
            });
            if !current {
                self.scheduler
                    .lock()
                    .window
                    .reject_delivery(hash, None, now);
            }
            if rejected == RejectDelivery::ReleasedPending {
                retry_count = retry_count.saturating_add(1);
                if let Some(source) = source {
                    if self.peer_table.disconnect_source(source) {
                        self.scheduler
                            .lock()
                            .window
                            .mark_peer_unresponsive(source, now);
                        tracing::warn!(peer_addr = ?source.endpoint, %hash, "block sync: peer served mutated block body; disconnecting");
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

/// Whether a body that no connection has in flight may stage: Core's `AcceptBlock`
/// acceptance for `fRequested == false` (validation.cpp), plus an
/// active-branch clause.
///
/// INVARIANT: reads only the tree and the two tip snapshots.
pub(super) fn unrequested_body_admissible(
    tree: &BlockTree,
    hash: Hash256,
    chain_tip: Option<&TipSnapshot>,
    applied_tip: Option<&TipSnapshot>,
    minimum_chain_work: [u8; 32],
) -> bool {
    let Some(node_id) = tree.lookup(hash) else {
        return true;
    };
    let Ok(node) = tree.node(node_id) else {
        return true;
    };
    let Some(chain_tip) = chain_tip else {
        return false;
    };
    let max_height = applied_tip.map_or(CORE_REORG_SAFETY_MARGIN - 1, |tip| {
        tip.height.saturating_add(CORE_REORG_SAFETY_MARGIN)
    });
    let node_work: [u8; 32] = node.chainwork.to_be_bytes();
    tree.node_at_height_from(chain_tip.tip_id, node.height) == Some(node_id)
        && applied_tip.is_none_or(|tip| node.chainwork >= tip.chainwork)
        && node_work >= minimum_chain_work
        && node.height <= max_height
}
