//! The ordered durable commit between chain mutation and publication.
use super::error::ApplyError;
use super::publication::{publish_applied, tx_count_delta_for};
use super::{BlockProvenance, Chainstate, ProvenApply, PublishMode};
use bitcoin_rs_chain::{ChainTxCount, TipSnapshot};
use bitcoin_rs_primitives::{Block, Hash256, OutPoint};
use bitcoin_rs_storage::{CommitRecords, DurableHead};
use bitcoin_rs_utxo::UtxoCoin;
use bitcoin_rs_utxo::contract::{
    OutputSource, RollbackError, UndoLoadError, load_block_undo, rollback_block_recovery,
};

/// What one durable head commit certified: the commit id and the exact
/// cumulative transaction count publication may carry. A receipt exists only
/// for a committed head, so publication cannot carry an uncommitted count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DurableReceipt {
    pub(super) commit_id: u64,
    pub(super) chain_tx_count: ChainTxCount,
}

impl DurableReceipt {
    /// The receipt of an already committed head. Replay never mints a commit:
    /// it republishes under this receipt.
    fn from_head(head: &DurableHead) -> Self {
        Self {
            commit_id: head.commit_id,
            chain_tx_count: ChainTxCount::from_wire(head.chain_tx_count),
        }
    }

    pub(super) fn certify(self, mut tip: TipSnapshot) -> TipSnapshot {
        tip.chain_tx_count = self.chain_tx_count;
        tip
    }
}

/// Facts of one connected block that its durable head commit names.
pub(super) struct ConnectCommitFacts {
    /// Parent the durable head must currently name — for a group, the parent
    /// of its first block. Any other stored tip is divergence the commit
    /// refuses rather than advance a head whose lineage would break.
    pub prev_hash: Hash256,
    pub tip: Hash256,
    pub height: u32,
    pub chain_tx_count_after: u64,
    /// Newest undo row this commit certifies: a connect or group names its
    /// last block, a disconnect keeps the prior extent.
    pub undo_extent: Option<(u32, Hash256)>,
}

/// Makes the appended block data durable before the head may name it.
pub(super) fn sync_appended_blocks(handles: &Chainstate) -> Result<(), ApplyError> {
    let Some(store) = handles.block_body_store.as_ref() else {
        return Ok(());
    };
    store.sync().map_err(ApplyError::DurableHeadCommit)
}

/// Advances the durable head for one connected block.
pub(super) fn commit_connect_head(
    handles: &Chainstate,
    facts: &ConnectCommitFacts,
    records: &CommitRecords<'_>,
) -> Result<DurableReceipt, ApplyError> {
    let prior = handles
        .durable_head
        .load()
        .map_err(ApplyError::DurableHeadCommit)?;
    if let Some(head) = prior.as_ref() {
        // Recovery replays to the head at boot, so a connect must always
        // extend the head exactly.
        if head.tip != facts.prev_hash {
            return Err(ApplyError::DurableHeadLineage {
                head: head.tip,
                prev: facts.prev_hash,
            });
        }
    }
    let next = DurableHead {
        commit_id: prior.as_ref().map_or(1, |head| head.commit_id + 1),
        height: facts.height,
        tip: facts.tip,
        chain_tx_count: facts.chain_tx_count_after,
        body_extent: handles
            .block_body_store
            .as_ref()
            .and_then(|store| store.append_cursor()),
        undo_extent: facts.undo_extent,
    };
    handles
        .durable_head
        .commit(prior.as_ref(), &next, records)
        .map_err(ApplyError::DurableHeadCommit)?;
    metrics::counter!("node.durable_head.commits").increment(1);
    Ok(DurableReceipt::from_head(&next))
}

/// Resolves the stored flat-file locator of one committed block, when the
/// store indexes positions. A group lands one locator row per block.
pub(super) fn stored_body_row(
    handles: &Chainstate,
    height: u32,
    hash: Hash256,
) -> Result<Option<(u32, Hash256, bitcoin_rs_storage::BlockFilePosition)>, ApplyError> {
    let Some(store) = handles.block_body_store.as_ref() else {
        return Ok(None);
    };
    Ok(store
        .block_position(height, hash)
        .map_err(ApplyError::DurableHeadCommit)?
        .map(|position| (height, hash, position)))
}

/// Advances the durable head for one disconnected block.
pub(super) fn commit_disconnect_head(
    handles: &Chainstate,
    parent_tip: &bitcoin_rs_chain::TipSnapshot,
    disconnected_hash: Hash256,
    chain_tx_count_after: u64,
) -> Result<DurableReceipt, ApplyError> {
    let prior = handles
        .durable_head
        .load()
        .map_err(ApplyError::DurableHeadCommit)?;
    let Some(head) = prior.as_ref() else {
        return Err(ApplyError::DurableHeadCommit(
            bitcoin_rs_storage::StorageError::InvalidOperation(
                "disconnect with no durable head committed",
            ),
        ));
    };
    if head.tip != disconnected_hash {
        return Err(ApplyError::DurableHeadLineage {
            head: head.tip,
            prev: disconnected_hash,
        });
    }
    let next = DurableHead {
        commit_id: head.commit_id + 1,
        height: parent_tip.height,
        tip: parent_tip.hash,
        chain_tx_count: chain_tx_count_after,
        body_extent: head.body_extent,
        undo_extent: head.undo_extent,
    };
    handles
        .durable_head
        .commit(Some(head), &next, &CommitRecords::default())
        .map_err(ApplyError::DurableHeadCommit)?;
    metrics::counter!("node.durable_head.commits").increment(1);
    Ok(DurableReceipt::from_head(&next))
}

/// Resolves one replayed block's spends from its own durable undo row. The
/// head certifies undo record and body in one batch, so the restored coins
/// are exactly the inputs the committed block saw.
struct UndoRowSpends<'a>(&'a bitcoin_rs_utxo::contract::UndoBatch);

impl OutputSource for UndoRowSpends<'_> {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<UtxoCoin> {
        self.0
            .restores()
            .iter()
            .find(|add| &add.outpoint == outpoint)
            .map(|add| UtxoCoin {
                outpoint: add.outpoint,
                txout: add.txout.clone(),
                coinbase: add.coinbase,
                height: add.height,
            })
    }
}

/// Boot-time reconciliation of the stored head against the restored tip.
pub(crate) fn reconcile_at_boot(handles: &Chainstate) -> Result<(), ApplyError> {
    let stored = handles
        .durable_head
        .load()
        .map_err(ApplyError::DurableHeadCommit)?;
    let Some(head) = stored else {
        return Ok(());
    };
    let restored = handles.applied_tip.load_full();
    if restored.as_ref().is_some_and(|tip| tip.hash == head.tip) {
        return Ok(());
    }
    replay_committed_gap(handles, head, restored.as_deref())
}

/// Reconciles disconnect evidence before the node accepts work.
pub fn recover_disconnect_marker(handles: &Chainstate) -> Result<(), ApplyError> {
    let marker = handles
        .undo_store
        .load_disconnect_marker()
        .map_err(ApplyError::UndoPersistence)?;
    let Some(marker) = marker else {
        return reconcile_at_boot(handles);
    };
    let fail_closed = |head_tip: Hash256, head_height: u32, reason: &'static str| {
        ApplyError::DurableHeadGapUnrecoverable {
            head_tip,
            head_height,
            restored_tip: handles.applied_tip.load_full().map(|tip| tip.hash),
            restored_height: handles.applied_tip.load_full().map(|tip| tip.height),
            reason,
        }
    };
    let Some(head) = handles
        .durable_head
        .load()
        .map_err(ApplyError::DurableHeadCommit)?
    else {
        return Err(fail_closed(
            marker.hash,
            marker.height,
            "a disconnect marker exists with no durable head to reconcile it against",
        ));
    };
    // Gap replay is valid only when the restored tip already lies on the
    // certified head chain. Height alone cannot answer that: a checkpointed
    // tip can sit below the head on a branch a reorg already left. The head
    // tip itself may be absent from the restored tree, so the tip is measured
    // against the deepest head-chain point the tree resolves. Anything else
    // must first rewind to the fork through the stored undo rows.
    let restored = handles.applied_tip.load_full();
    let mode = match restored.as_deref() {
        None => "cold-replay",
        Some(tip) => {
            let anchor = resolve_head_anchor(handles, &head)?;
            if anchor.contains_tip(handles, tip) {
                "gap-replay"
            } else {
                rewind_restored_to_head(handles, &head, &anchor)?;
                "checkpoint-rewind"
            }
        }
    };
    reconcile_at_boot(handles)?;
    tracing::warn!(
        height = marker.height,
        hash = %marker.hash,
        head = %head.tip,
        head_height = head.height,
        mode,
        "automatic disconnect recovery replayed the certified head chain"
    );
    // Publication is the durability fence: the recovery checkpoint retires
    // the marker only after the repaired state, the journal compaction, and
    // the resume all land. A failure retains it.
    if let Err(error) = handles.publish_recovery_checkpoint() {
        return Err(ApplyError::RecoveryPublication(Box::new(error)));
    }
    Ok(())
}

/// The deepest point of the certified head chain the restored block tree
/// resolves. When the head tip is itself a tree node the anchor is the head
/// and `above` is empty; otherwise the anchor is the first head-chain
/// ancestor the tree knows, found by walking the self-authenticating durable
/// body chain down from `head.tip`.
#[derive(Debug)]
struct HeadChainAnchor {
    pub(super) anchor_height: u32,
    pub(super) anchor: Hash256,
    /// Head-chain `(height, hash)` pairs strictly above the anchor, ascending
    /// — the segment the tree cannot resolve.
    pub(super) above: Vec<(u32, Hash256)>,
}

impl HeadChainAnchor {
    /// Whether `tip` lies on the head chain the anchor certifies: at or below
    /// the anchor it must be its ancestor; above it the tip must equal the
    /// descriptor the body walk recorded at that height.
    fn contains_tip(&self, handles: &Chainstate, tip: &TipSnapshot) -> bool {
        if tip.height <= self.anchor_height {
            let tree = handles.block_tree.read();
            return tree.lookup(self.anchor).is_some_and(|anchor_id| {
                tree.find_common_ancestor(anchor_id, tip.tip_id) == Some(tip.tip_id)
            });
        }
        let index = usize::try_from(tip.height - self.anchor_height - 1).unwrap_or(usize::MAX);
        self.above
            .get(index)
            .is_some_and(|(_, hash)| *hash == tip.hash)
    }
}

/// Resolves the deepest head-chain point the restored block tree knows.
fn resolve_head_anchor(
    handles: &Chainstate,
    head: &DurableHead,
) -> Result<HeadChainAnchor, ApplyError> {
    if handles.block_tree.read().lookup(head.tip).is_some() {
        return Ok(HeadChainAnchor {
            anchor_height: head.height,
            anchor: head.tip,
            above: Vec::new(),
        });
    }
    let Some(store) = handles.block_body_store.as_ref() else {
        return Err(rewind_refused(
            handles,
            head,
            "the durable head tip is absent from the block tree and no body store is attached",
        ));
    };
    let mut above = Vec::new();
    let mut cursor = (head.height, head.tip);
    loop {
        let bytes = store
            .load_block_body(cursor.0, cursor.1)
            .map_err(ApplyError::BlockBodyPersistence)?
            .ok_or_else(|| {
                rewind_refused(
                    handles,
                    head,
                    "a durable head body is missing, so the head chain cannot be authenticated",
                )
            })?;
        let block: Block = bitcoin_rs_primitives::deserialize(&bytes)
            .map_err(|_| rewind_refused(handles, head, "a durable head body does not decode"))?;
        if block.block_hash().0 != cursor.1 {
            return Err(rewind_refused(
                handles,
                head,
                "a durable head body does not hash to its committed hash",
            ));
        }
        above.push(cursor);
        if cursor.0 == 0 {
            return Err(rewind_refused(
                handles,
                head,
                "no durable head ancestor resolves in the restored block tree",
            ));
        }
        let parent = block.header.prev_blockhash.0;
        if handles.block_tree.read().lookup(parent).is_some() {
            above.reverse();
            return Ok(HeadChainAnchor {
                anchor_height: cursor.0 - 1,
                anchor: parent,
                above,
            });
        }
        cursor = (cursor.0 - 1, parent);
    }
}

/// The single fail-closed refusal every recovery step reports, naming the
/// stored head and the state recovery found.
fn gap_unrecoverable(
    head: &DurableHead,
    restored: Option<&TipSnapshot>,
    reason: &'static str,
) -> ApplyError {
    ApplyError::DurableHeadGapUnrecoverable {
        head_tip: head.tip,
        head_height: head.height,
        restored_tip: restored.map(|tip| tip.hash),
        restored_height: restored.map(|tip| tip.height),
        reason,
    }
}

/// [`gap_unrecoverable`] against whatever tip is currently applied, for the
/// rewind walk that moves that tip as it goes.
fn rewind_refused(handles: &Chainstate, head: &DurableHead, reason: &'static str) -> ApplyError {
    gap_unrecoverable(head, handles.applied_tip.load_full().as_deref(), reason)
}

/// Rolls a restored state that leads the durable head back onto that head,
/// one block at a time, under a single transition.
fn rewind_restored_to_head(
    handles: &Chainstate,
    head: &DurableHead,
    anchor: &HeadChainAnchor,
) -> Result<(), ApplyError> {
    let transition = handles.begin_transition()?;
    let walked = loop {
        let applied = match handles.applied_tip.load_full() {
            Some(applied) => applied,
            None => {
                break Err(rewind_refused(
                    handles,
                    head,
                    "the applied tip vanished mid-rewind",
                ));
            }
        };
        if anchor.contains_tip(handles, &applied) {
            break Ok(());
        }
        if let Err(error) = rewind_one_step(handles, head, &applied) {
            break Err(error);
        }
    };
    drop(transition);
    walked
}

/// Rolls one applied block back against the undo row its head commit
/// certified, then publishes the parent tip the stored head names.
fn rewind_one_step(
    handles: &Chainstate,
    head: &DurableHead,
    applied: &TipSnapshot,
) -> Result<(), ApplyError> {
    let height = applied.height;
    let hash = applied.hash;
    let Some(store) = handles.block_body_store.as_ref() else {
        return Err(rewind_refused(
            handles,
            head,
            "no block body store is attached",
        ));
    };
    let bytes = store
        .load_block_body(height, hash)
        .map_err(ApplyError::BlockBodyPersistence)?
        .ok_or_else(|| rewind_refused(handles, head, "a rewound block body is missing"))?;
    let block: Block = bitcoin_rs_primitives::deserialize(&bytes)
        .map_err(|_| rewind_refused(handles, head, "a rewound block body does not decode"))?;
    if block.block_hash().0 != hash {
        return Err(rewind_refused(
            handles,
            head,
            "a rewound block body does not hash to the applied tip",
        ));
    }
    // A header-matching body can still carry altered transactions; the
    // txid-level merkle check the ordinary disconnect path runs applies
    // here for the same reason.
    let txids: Vec<bitcoin_rs_primitives::Txid> = block
        .txs
        .iter()
        .map(bitcoin_rs_primitives::Tx::txid)
        .collect();
    if bitcoin_rs_consensus::verify_merkle_root_with_txids(&block, &txids).is_err() {
        return Err(rewind_refused(
            handles,
            head,
            "a rewound block body does not match its header's merkle root",
        ));
    }
    let undo = load_block_undo(handles.undo_store.as_ref(), height, hash).map_err(|_| {
        rewind_refused(handles, head, "a rewound block's undo record does not load")
    })?;
    let tx_count_delta = tx_count_delta_for(&block);
    let parent_tip = rewound_parent(handles, head, applied, &block, tx_count_delta)?;
    // Recovery owns the surviving marker — the ordinary path's arming
    // guard would refuse every step under it, and overwriting it would
    // erase the evidence being reconciled.
    rollback_block_recovery(
        handles.utxo.as_ref(),
        handles.coin_stats.as_ref(),
        height,
        parent_tip.height,
        tx_count_delta,
        &undo,
    )
    .map_err(|error| match error {
        RollbackError::Refused(_) => {
            rewind_refused(handles, head, "the disconnect marker refused the rewind")
        }
        RollbackError::Utxo(_) => rewind_refused(
            handles,
            head,
            "the UTXO set refused the rewind to the durable head",
        ),
        RollbackError::CoinStats(_) => rewind_refused(
            handles,
            head,
            "the coin statistics refused the rewind to the durable head",
        ),
        RollbackError::Marker(_) => rewind_refused(
            handles,
            head,
            "the disconnect marker did not record the rewind",
        ),
    })?;
    publish_applied(handles, &parent_tip, crate::events::HintKind::Disconnected);
    Ok(())
}

/// The parent tip one rewind step lands on, resolved against the block tree
/// and the block's own previous hash.
fn rewound_parent(
    handles: &Chainstate,
    head: &DurableHead,
    applied: &TipSnapshot,
    block: &Block,
    tx_count_delta: u64,
) -> Result<TipSnapshot, ApplyError> {
    let tree = handles.block_tree.read();
    let node = tree.node(applied.tip_id)?;
    let parent_id = node
        .parent
        .ok_or_else(|| rewind_refused(handles, head, "the applied tip has no parent node"))?;
    let parent = tree.node(parent_id)?;
    if parent.height + 1 != node.height {
        return Err(rewind_refused(
            handles,
            head,
            "the parent node's height does not step down from the applied tip",
        ));
    }
    let parent_tip = TipSnapshot {
        tip_id: parent_id,
        height: parent.height,
        chainwork: parent.chainwork,
        hash: parent.hash,
        chain_tx_count: applied.chain_tx_count.rewind(tx_count_delta),
    };
    if parent_tip.hash != block.header.prev_blockhash.0 {
        return Err(rewind_refused(
            handles,
            head,
            "the rewound parent does not match the block's own previous hash",
        ));
    }
    Ok(parent_tip)
}

/// Replays the committed-but-unpublished gap onto the restored chainstate:
/// every authenticated durable-head body above `restored`, or the complete
/// certified head chain when `restored` is `None`.
fn replay_committed_gap(
    handles: &Chainstate,
    head: DurableHead,
    restored: Option<&TipSnapshot>,
) -> Result<(), ApplyError> {
    let unrecoverable = |reason: &'static str| gap_unrecoverable(&head, restored, reason);
    // The first height the replay must re-apply: the restored tip's child,
    // or genesis when nothing was restored.
    let base_height = match restored {
        Some(tip) => {
            if head.height <= tip.height {
                return Err(unrecoverable(
                    "the restored tip is not below the stored head; the state is not a publication lag",
                ));
            }
            tip.height + 1
        }
        None => 0,
    };
    // Width bounds the descriptor allocation only; the body-identity and
    // ancestry checks below decide recoverability.
    let gap_width = usize::try_from(head.height - base_height + 1)
        .map_err(|_| unrecoverable("gap width exceeds the address space"))?;

    let Some(store) = handles.block_body_store.as_ref() else {
        return Err(unrecoverable("no block body store is attached"));
    };
    let load_body = |height: u32, hash: Hash256| -> Result<(Block, Vec<u8>), ApplyError> {
        let bytes = store
            .load_block_body(height, hash)
            .map_err(ApplyError::BlockBodyPersistence)?
            .ok_or_else(|| unrecoverable("a committed gap body is missing from storage"))?;
        let block: Block = bitcoin_rs_primitives::deserialize(&bytes)
            .map_err(|_| unrecoverable("a committed gap body does not decode"))?;
        if block.block_hash().0 != hash {
            return Err(unrecoverable(
                "a stored body does not hash to its committed hash",
            ));
        }
        Ok((block, bytes))
    };

    // Walk the head chain down to the base, keeping only hash descriptors.
    let mut chain = Vec::with_capacity(gap_width);
    let mut cursor = (head.height, head.tip);
    loop {
        let (block, _) = load_body(cursor.0, cursor.1)?;
        let parent = block.header.prev_blockhash.0;
        chain.push(cursor);
        if cursor.0 == base_height {
            let expected_parent = restored.map_or_else(Hash256::default, |tip| tip.hash);
            if parent != expected_parent {
                return Err(unrecoverable(
                    "the head chain does not descend from the restored tip",
                ));
            }
            break;
        }
        cursor = (cursor.0 - 1, parent);
    }
    chain.reverse();
    replay_gap_chain(handles, head, chain, restored, load_body)
}

/// Re-applies the walked head chain through the ordinary commit path under
/// one transition and publishes the state the head already certified.
fn replay_gap_chain(
    handles: &Chainstate,
    head: DurableHead,
    chain: Vec<(u32, Hash256)>,
    restored: Option<&TipSnapshot>,
    load_body: impl Fn(u32, Hash256) -> Result<(Block, Vec<u8>), ApplyError>,
) -> Result<(), ApplyError> {
    let unrecoverable = |reason: &'static str| gap_unrecoverable(&head, restored, reason);
    let transition = handles.begin_transition()?;
    // A length always fits u64; the metrics counter counts in u64.
    let replayed_blocks = u64::try_from(chain.len()).unwrap_or(u64::MAX);
    let replayed = (|| {
        let mut commit_id = 0_u64;
        for (height, hash) in chain {
            let (block, bytes) = load_body(height, hash)?;
            let bytes = bytes::Bytes::from(bytes);
            // The head batch certifies the undo row in the same receipt as
            // the body, so the coins it restores are exactly the inputs the
            // committed block saw: resolving replay against it redoes the
            // committed mutation even on a cold chainstate, where the live
            // set has not been rebuilt. A missing row falls back to the live
            // set a restored tip still carries; an unreadable one fails closed.
            let proven = match load_block_undo(handles.undo_store.as_ref(), height, hash) {
                Ok(undo) => Some(ProvenApply::AssumeValidSkipped(
                    super::prepare::prepare_apply(
                        &block,
                        Some(bytes.clone()),
                        &UndoRowSpends(&undo),
                        handles.validation_engine,
                    )?,
                )),
                Err(UndoLoadError::Missing { .. }) => None,
                Err(_) => {
                    return Err(unrecoverable("a committed gap undo record does not load"));
                }
            };
            let outcome = super::connect::apply_committed_block_admitted(
                handles,
                &block,
                Some(bytes),
                proven,
                BlockProvenance::LocalReplay,
                PublishMode::Replay {
                    receipt: DurableReceipt::from_head(&head),
                },
            )?;
            commit_id = outcome.commit_id;
            tracing::debug!(height, hash = %hash.to_string_be(), "replayed committed gap block");
        }
        let published = handles.applied_tip.load_full();
        // A head stored before counts were tracked records the unknown
        // marker (wire 0): replay may reconstruct a real count, so the count
        // is part of the landing check only when the head actually knows it.
        let (head_tip, head_height, head_count, head_commit) =
            (head.tip, head.height, head.chain_tx_count, head.commit_id);
        let landed = published.as_ref().is_some_and(|tip| {
            tip.hash == head_tip
                && tip.height == head_height
                && commit_id == head_commit
                && (head_count == 0 || tip.chain_tx_count.to_wire() == head_count)
        });
        if !landed {
            return Err(unrecoverable("replay finished short of the stored head"));
        }
        Ok(commit_id)
    })();
    let commit_id = match replayed {
        Ok(commit_id) => commit_id,
        Err(error) => {
            handles.fail_closed_for_recovery();
            drop(transition);
            return Err(error);
        }
    };
    drop(transition);
    metrics::counter!("node.durable_head.recovery_gaps_replayed").increment(replayed_blocks);
    metrics::counter!("node.durable_head.recovery_gaps").increment(1);
    tracing::info!(
        head_height = head.height,
        head_tip = %head.tip.to_string_be(),
        restored_height = restored.map(|tip| tip.height),
        blocks = replayed_blocks,
        commit_id,
        "replayed the committed-but-unpublished gap; the node resumes on the stored head"
    );
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/durable_replay_tests.rs"]
mod tests;
