//! Bounded inbound body draining and exact staged-body admission.

use super::BlockSync;
use super::chain::HeaderAdmission;
use super::chain::SyncChainError;
use super::peers::is_peer_fault;
use crate::InboundBlock;
use crate::RejectDelivery;
use crate::StagedBlock;
use crate::connection::PeerSource;
use crate::download_window::INBOUND_BLOCK_STAGE_CHUNK;
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

/// Which window credit a staged delivery earns once the delivering
/// connection is proven current under table authority.
#[derive(Clone, Copy)]
enum DeliveryCredit {
    /// The block was already staged: only the pending-timeout observation
    /// resolves.
    Duplicate,
    /// A first-copy delivery: timeout, cold-front, probe, and stall progress,
    /// gated on the height the pending carried at removal.
    Delivery(Option<u32>),
}

impl BlockSync {
    /// Drains delivered bodies, admits their carried headers, and prunes
    /// staging timeouts.
    ///
    /// PRE: `now` is the tick's clock reading, or the reading of the caller
    ///   that owns the pacing decision.
    /// POST: every header blame, cooldown stamp, and follow-up header request
    ///   the drain makes is evaluated at `now`. Expired staging bodies are
    ///   pruned against a wall reading taken after this drain stages them, so
    ///   a body delivered now is never judged expired by the caller's clock.
    /// INVARIANT: no peer-facing timing decision in this path reads
    ///   `Instant::now()` while its counterpart on the tick path reads `now`.
    pub(super) fn drain_inbound_blocks(&self, now: Instant) {
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

        self.admit_staged_headers(now);

        let now = Instant::now();
        let dropped = self.scheduler.lock().stager.prune_expired(now);
        let pruned = !dropped.is_empty();
        if pruned {
            // The tree owns heights: a pruned body requeues at its tree
            // height, or without a cursor move when the tree cannot resolve
            // it (the old 0-sentinel rewind to genesis is unrepresentable).
            let requeues: Vec<(Hash256, Option<u32>)> = dropped
                .iter()
                .map(|dropped| {
                    let height = {
                        let tree = self.chain.block_tree().read();
                        tree.lookup(dropped.hash)
                            .and_then(|node_id| tree.node(node_id).ok())
                            .map(|node| node.height)
                    };
                    (dropped.hash, height)
                })
                .collect();
            let mut scheduler = self.scheduler.lock();
            for (hash, height) in requeues {
                scheduler.window.requeue_for_retry(&hash, height, now);
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
        saw_block: &mut bool,
        next_expected_hash: &mut Option<Hash256>,
        apply_head_check: &mut Option<Hash256>,
    ) -> bool {
        let receiver = self.inbound_blocks_rx.lock();
        while blocks.len() < INBOUND_BLOCK_STAGE_CHUNK {
            let Ok(inbound) = receiver.try_recv() else {
                return true;
            };
            if !*saw_block {
                *next_expected_hash = self.next_expected_block_hash();
                *apply_head_check = next_expected_hash
                    .as_ref()
                    .copied()
                    .filter(|hash| *hash != Hash256::from(inbound.block.block_hash()));
            }
            blocks.push(inbound);
            *saw_block = true;
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
        Self::is_ancestor_at_height(
            tree,
            applied_tip.tip_id,
            applied_tip.height,
            active_tip.tip_id,
        )
        .then_some(active_tip.tip_id)
    }

    /// Retries header admission for staged bodies whose headers are still
    /// absent from the tree.
    ///
    /// The listener forwards every inbound body's embedded header through
    /// the headers drain, but a refused batch or a source-less delivery
    /// leaves the body staged without a tree node — and
    /// `apply_buffered_blocks` only drains hashes the tree knows, so the
    /// body would otherwise sit until its staged timeout despite being
    /// complete. `MissingParent` keeps the body staged and asks an eligible
    /// peer for the missing ancestry; `TimestampTooFarAhead` retries
    /// naturally each drain and admits once the header enters the allowed
    /// window; a permanently inadmissible header (a peer-fault rejection)
    /// means the body can never apply, so it is discarded instead of paying
    /// the same admission retry every drain — and its delivering peer
    /// carries the fault, exactly as a rejected `headers` batch would.
    fn admit_staged_headers(&self, now: Instant) {
        let unadmitted: Vec<(Hash256, Header, Option<crate::PeerSource>)> = {
            let tree = self.chain.block_tree().read();
            let scheduler = self.scheduler.lock();
            scheduler
                .stager
                .staged_headers()
                .filter(|(hash, _, _)| tree.lookup(*hash).is_none())
                .collect()
        };
        // Every staged header reaches `route_headers_batch`, and a
        // rejection can still commit a valid prefix. A batch the presync
        // state absorbs retires here and retries once it is committed.
        let mut missing_parent = false;
        let mut credit_refresh_needed = false;
        let mut invalid: Vec<(Hash256, Option<crate::PeerSource>)> = Vec::new();
        for (hash, header, source) in unadmitted {
            let Some(admission) =
                self.route_headers_batch(&[header], source, false, 1, Instant::now())
            else {
                continue;
            };
            match admission {
                HeaderAdmission::Accepted {
                    announced_tip: Some(tip_hash),
                    active_height,
                    ..
                } => {
                    // A staged retry that now admits is the same
                    // announcement the headers drain credits — the
                    // delivering connection demonstrated the tip even if
                    // its forwarded batch raced or was refused.
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
            // The body's header can never admit: drop the staged entry AND
            // the window's delivery record outright — re-queuing would just
            // re-download a body that cannot apply. Then blame the
            // delivering peer: a body whose embedded header fails consensus
            // is the peer's fault, same as a rejected `headers` batch.
            // PeerTable operations precede the scheduler lock to preserve
            // the PeerTable → scheduler ordering used elsewhere.
            let blamed: Vec<std::net::SocketAddr> = invalid
                .iter()
                .filter_map(|(_, source)| *source)
                .filter(|source| {
                    if self.peer_table.disconnect_source(*source) {
                        // Every removal path releases a `getheaders` gate
                        // the peer owned, or a same-address reconnect
                        // inherits a dead deadline.
                        self.clear_header_request_for(*source);
                        true
                    } else {
                        false
                    }
                })
                .map(|source| source.addr)
                .collect();
            let mut scheduler = self.scheduler.lock();
            for (hash, _) in &invalid {
                scheduler.stager.discard(hash);
            }
            for peer_addr in &blamed {
                scheduler.window.mark_peer_unresponsive(*peer_addr, now);
            }
            tracing::debug!(
                discarded = invalid.len(),
                "block sync: discarded bodies with inadmissible headers"
            );
        }
        if credit_refresh_needed {
            self.refresh_active_peer_credit();
        }
        // A staged retry that just admitted may have attached the ancestry
        // a deferred owned fetch was waiting on — resolve it now.
        self.resolve_owned_body_fetches();
        if missing_parent {
            self.request_headers_from_eligible(now);
        }
    }

    /// Stages one chunk of delivered bodies.
    ///
    /// PRE: `blocks` is non-empty; `next_expected_hash` is the apply
    ///   frontier's next hash when one is known.
    /// POST: `blocks` is empty; returns how many bodies were staged, found
    ///   already staged, or rejected for a failed body/header binding. A
    ///   body that no connection has in flight stages only when
    ///   `unrequested_body_admissible` holds; any other such body is
    ///   discarded with no retry and is not counted.
    /// INVARIANT: an unrequested body whose tree-resolved node fails an
    ///   admission clause is never staged.
    #[allow(clippy::too_many_lines)]
    pub(super) fn buffer_received_block_chunk(
        &self,
        blocks: &mut Vec<InboundBlock>,
        next_expected_hash: Option<Hash256>,
    ) -> usize {
        // A cold-start hedge can arrive after its original copy was applied.
        // Drop only blocks proven to lie on the applied ancestry; a known
        // side-chain block at the same or lower height must remain eligible.
        if let Some(applied_tip) = self.chain.applied_tip().load_full() {
            let tree = self.chain.block_tree().read();
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

        // Already-staged precheck: skip the expensive body-binding hashes for
        // blocks whose hash is already in the stager. A correct body already
        // staged must not be displaced by a late malformed duplicate (P2-3).
        //
        // The same pass gates unrequested bodies: a body that no connection
        // has in flight (Core's `fRequested` is false) stages only when
        // Core's `AcceptBlock` would process it. A discarded body leaves no
        // staged state and queues no retry. Lock order: tree, then scheduler.
        let already_staged: Vec<bool> = {
            let chain_tip = self.chain.chain_tip().load_full();
            let applied_tip = self.chain.applied_tip().load_full();
            let minimum_chain_work = self.chain.network().minimum_chain_work();
            let tree = self.chain.block_tree().read();
            let scheduler = self.scheduler.lock();
            let offered = blocks.len();
            let mut already_staged = Vec::with_capacity(offered);
            blocks.retain(|inbound| {
                let hash = Hash256::from(inbound.block.block_hash());
                let staged = scheduler.stager.contains(&hash);
                let admitted = staged
                    || scheduler.window.contains_pending(&hash)
                    || unrequested_body_admissible(
                        &tree,
                        hash,
                        chain_tip.as_deref(),
                        applied_tip.as_deref(),
                        minimum_chain_work,
                    );
                if admitted {
                    already_staged.push(staged);
                }
                admitted
            });
            let discarded = offered.saturating_sub(blocks.len());
            if discarded > 0 {
                tracing::debug!(
                    discarded,
                    "block sync: discarded unrequested bodies Core would not process"
                );
            }
            already_staged
        };

        // For non-staged blocks, the chain side derives segwit_active from
        // the tree (the same canonical softfork_state path as apply) and runs
        // the consensus body-binding check, so the gate reproduces exact
        // consensus semantics without the executor owning the rule.
        let binding_results: Vec<Result<(), SyncChainError>> = blocks
            .iter()
            .zip(&already_staged)
            .map(|(inbound, already_staged)| {
                if *already_staged {
                    Ok(())
                } else {
                    self.chain.check_body_binding(&inbound.block)
                }
            })
            .collect();

        // Stager lock: TOCTOU recheck + insert. Binding-failed blocks are
        // tracked separately for the window's source-aware reject_delivery.
        let mut staged_blocks = Vec::with_capacity(blocks.len());
        let mut reject_deliveries = Vec::new();
        let now = Instant::now();
        {
            let mut scheduler = self.scheduler.lock();
            let stager = &mut scheduler.stager;
            for (inbound, (already_staged, binding_result)) in blocks
                .drain(..)
                .zip(already_staged.into_iter().zip(binding_results))
            {
                let hash = Hash256::from(inbound.block.block_hash());
                let source = inbound.source;
                // The body has left the ingress channel: release the
                // delivering connection's unsolicited forwarding slot. What
                // follows - staging, discarding, or rejecting - is sync's.
                drop(inbound.forward_credit);
                if already_staged {
                    staged_blocks.push((hash, source, StagedBlock::AlreadyStaged));
                    continue;
                }
                // Issue #1070: the header-derived block hash does not bind the
                // delivered transaction or witness bytes by itself. The
                // stager keeps the first body per hash, so reject any body
                // whose txid Merkle tree or witness commitment does not bind
                // to the header before it can occupy that slot.
                if let Err(error) = binding_result {
                    metrics::counter!("node.sync.body_binding_drops").increment(1);
                    let witness = inbound
                        .block
                        .txs
                        .first()
                        .and_then(|tx| tx.inputs.first())
                        .map(|input| &input.witness);
                    tracing::warn!(
                        %hash, %error, ?source,
                        serialized_bytes = inbound.serialized.len(),
                        transactions = inbound.block.txs.len(),
                        coinbase_witness_items = witness.map_or(0, bitcoin_rs_primitives::Witness::len),
                        coinbase_witness_first_bytes = witness.and_then(|stack| stack.first()).map_or(0, Vec::len),
                        "block sync: body/header binding failed; rejecting delivery"
                    );
                    reject_deliveries.push((hash, source));
                    continue;
                }
                // TOCTOU: recheck under the stager lock before inserting.
                if stager.contains(&hash) {
                    staged_blocks.push((hash, source, StagedBlock::AlreadyStaged));
                    continue;
                }
                let staged = stager.insert(
                    hash,
                    next_expected_hash,
                    inbound.block,
                    inbound.serialized,
                    source,
                    now,
                );
                staged_blocks.push((hash, source, staged));
            }
        }

        // Resolve staged sources before taking the scheduler lock. Request
        // sends hold PeerTable's read lock while marking the window, so no
        // scheduler holder may acquire PeerTable in the opposite order.
        //
        // The source is the whole connection identity: a cancelled lease is
        // not a schedulable peer, so deliveries from one carry no credit.
        let staged_blocks: Vec<_> = staged_blocks
            .into_iter()
            .map(|(hash, source, staged)| {
                let source_peer = source.filter(|source| self.peer_table.is_current(*source));
                (hash, source_peer, staged)
            })
            .collect();

        // The block tree owns heights: bodies this insert count-evicts are
        // requeued at their tree-resolved heights, never at a stored sentinel
        // (there is no stored height). A hash the tree cannot resolve
        // requeues with no cursor move.
        let staged_blocks: Vec<_> = {
            let tree = self.chain.block_tree().read();
            staged_blocks
                .into_iter()
                .map(|(hash, source_peer, staged)| {
                    let resolve = |hash: Hash256| {
                        tree.lookup(hash)
                            .and_then(|node_id| tree.node(node_id).ok())
                            .map(|node| node.height)
                    };
                    let dropped_heights = match &staged {
                        StagedBlock::Memory { dropped, .. } => {
                            dropped.iter().map(|entry| resolve(entry.hash)).collect()
                        }
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
                        for (entry, height) in dropped.into_iter().zip(dropped_heights) {
                            window.requeue_for_retry(&entry.hash, height, now);
                            retry_count = retry_count.saturating_add(1);
                        }
                    }
                    StagedBlock::DroppedForRetry { dropped } => {
                        // Count-evicted before staging: release what the
                        // window holds without a cursor rewind.
                        window.requeue_for_retry(&dropped.hash, None, now);
                        retry_count = retry_count.saturating_add(1);
                        tracing::warn!(%hash, "block sync: received block buffer full; dropping block for retry");
                    }
                }
            }
        }
        // Delivery credit is stamped only while the delivering connection is
        // still current: `with_current` holds the table authority across the
        // window mutation, so a same-address replacement registering between
        // the liveness check above and this point voids the credit rather
        // than clearing stall or timeout state for a retired connection.
        for (hash, source_peer, credit) in delivery_credits {
            self.peer_table.with_current(source_peer, || {
                let mut scheduler = self.scheduler.lock();
                match credit {
                    DeliveryCredit::Duplicate => {
                        scheduler
                            .window
                            .credit_duplicate_delivery(hash, source_peer);
                    }
                    DeliveryCredit::Delivery(pending_height) => {
                        scheduler.window.credit_delivery_from(
                            hash,
                            source_peer,
                            pending_height,
                            now,
                        );
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
                            .mark_peer_unresponsive(source.addr, now);
                        tracing::warn!(peer_addr = %source.addr, %hash, "block sync: peer served mutated block body; disconnecting");
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

/// Whether a body that no connection has in flight may stage: Core's
/// `AcceptBlock` acceptance for `fRequested == false`
/// (validation.cpp:4327-4353), plus an active-branch clause.
///
/// PRE: `hash` names a body that is neither staged nor pending.
/// POST: `true` when the tree cannot resolve `hash` (the missing-header
/// path: the body applies once its ancestry lands); otherwise `true` only
/// when all four admission clauses below hold.
/// INVARIANT: reads only the tree and the two tip snapshots.
///
/// The admission clauses:
/// 1. The node lies on the header tip's branch.
/// 2. The node's chainwork is at least the applied tip's
///    (`fHasMoreOrSameWork`).
/// 3. The header tip's chainwork meets the network's minimum chain work.
/// 4. The node is at most `CORE_REORG_SAFETY_MARGIN` blocks above the
///    applied tip (`fTooFarAhead`).
///
/// Core checks the minimum-work floor on the body itself. Here the header
/// tip carries it: this window releases an expired request without
/// disconnecting its peer, so a late delivery during initial block
/// download must not be discarded only because its block predates the
/// floor. Clause 1 keeps a low-work side chain out on its own.
fn unrequested_body_admissible(
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
    // Core's `ActiveHeight()` is -1 on an empty chain.
    let max_height = applied_tip.map_or(CORE_REORG_SAFETY_MARGIN - 1, |tip| {
        tip.height.saturating_add(CORE_REORG_SAFETY_MARGIN)
    });
    // Big-endian, fixed width: byte order is numeric order.
    let tip_work: [u8; 32] = chain_tip.chainwork.to_be_bytes();
    tree.node_at_height_from(chain_tip.tip_id, node.height) == Some(node_id)
        && applied_tip.is_none_or(|tip| node.chainwork >= tip.chainwork)
        && tip_work >= minimum_chain_work
        && node.height <= max_height
}
