use super::error::ApplyError;
use super::tx_count_delta_for;
use super::{BlockProvenance, Chainstate, ProvenApply, PublishMode};
use crate::chain::{ChainTxCount, TipSnapshot};
use bitcoin_rs_consensus::primitives::{Block, BlockImage, Hash256, OutPoint};
use bitcoin_rs_storage::DurableHead;
use bitcoin_rs_storage::utxo::UtxoCoin;
use bitcoin_rs_storage::utxo::contract::{OutputSource, UndoLoadError, load_block_undo};

/// Proof that a connect replays the committed gap below the durable head.
///
/// In non-test builds, the private field ensures replay treatment is carried by
/// a value only the gap replay path can build.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReplayToken(());

#[cfg(test)]
pub(crate) fn replay_token_for_test() -> ReplayToken {
    ReplayToken(())
}

/// What one durable head commit certified: the commit id and the exact cumulative
/// transaction count publication may carry.
///
/// A receipt exists only for a committed head, so publication cannot carry an
/// uncommitted count.
#[derive(Clone, Copy, Debug)]
pub(super) struct DurableReceipt {
    pub(super) chain_tx_count: ChainTxCount,
}

impl DurableReceipt {
    fn from_head(head: &DurableHead) -> Self {
        Self {
            chain_tx_count: ChainTxCount::from_wire(head.chain_tx_count),
        }
    }

    pub(super) fn certify(self, mut tip: TipSnapshot) -> TipSnapshot {
        tip.chain_tx_count = self.chain_tx_count;
        tip
    }
}

pub(super) fn sync_appended_blocks(handles: &Chainstate) -> Result<(), ApplyError> {
    let Some(store) = handles.block_body_store.as_ref() else {
        return Ok(());
    };
    store.sync().map_err(ApplyError::DurableHeadCommit)
}

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

pub(super) fn commit_disconnect_head(
    handles: &Chainstate,
    parent_tip: &crate::chain::TipSnapshot,
    disconnected_hash: Hash256,
    chain_tx_count_after: u64,
    coin_delta: bitcoin_rs_storage::WindowDelta,
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
        assumeutxo: match head.assumeutxo {
            crate::AssumeUtxoDiskStatus::Finalized { base_height, .. }
                if parent_tip.height < base_height =>
            {
                crate::AssumeUtxoDiskStatus::Uninitialized
            }
            status => status,
        },
        commit_id: head.commit_id + 1,
        height: parent_tip.height,
        tip: parent_tip.hash,
        chain_tx_count: chain_tx_count_after,
        body_extent: head.body_extent,
        undo_extent: head.undo_extent,
    };
    let _receipt = handles
        .commit_authority
        .commit_disconnect(head, &next, coin_delta)
        .map_err(|error| match error {
            bitcoin_rs_storage::CommitError::Storage(s) => ApplyError::DurableHeadCommit(s),
            other => ApplyError::DurableHeadCommit(bitcoin_rs_storage::StorageError::backend(
                other.to_string(),
            )),
        })?;
    metrics::counter!("node.durable_head.commits").increment(1);
    Ok(DurableReceipt::from_head(&next))
}

struct UndoRowSpends<'a>(&'a bitcoin_rs_storage::utxo::contract::UndoBatch);

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
    replay_committed_gap(handles, &head, restored.as_deref())
}

pub fn recover_disconnect_marker(handles: &Chainstate) -> Result<(), ApplyError> {
    let marker = handles
        .undo_store
        .load_disconnect_marker()
        .map_err(ApplyError::UndoPersistence)?;
    let Some(head) = handles
        .durable_head
        .load()
        .map_err(ApplyError::DurableHeadCommit)?
    else {
        if let Some(marker) = marker {
            let fail_closed = |head_tip: Hash256, head_height: u32, reason: &'static str| {
                let restored = handles.applied_tip.load_full();
                ApplyError::DurableHeadGapUnrecoverable {
                    head_tip,
                    head_height,
                    restored_tip: restored.as_ref().map(|tip| tip.hash),
                    restored_height: restored.as_ref().map(|tip| tip.height),
                    reason,
                }
            };
            return Err(fail_closed(
                marker.hash,
                marker.height,
                "a disconnect marker exists with no durable head to reconcile it against",
            ));
        }
        return Ok(());
    };
    let restored = handles.applied_tip.load_full();
    let anchor = resolve_head_anchor(handles, &head)?;
    let needs_rewind = restored
        .as_deref()
        .is_some_and(|tip| !anchor.contains_tip(handles, tip));
    let mode = match restored.as_deref() {
        None => "cold-replay",
        Some(tip) => {
            if anchor.contains_tip(handles, tip) {
                "gap-replay"
            } else {
                rewind_restored_to_head(handles, &head, &anchor)?;
                "checkpoint-rewind"
            }
        }
    };
    reconcile_at_boot(handles)?;
    crate::recovery::settle_restored_coin_stats(handles, restored.as_deref())
        .map_err(|error| ApplyError::RecoveryCoinStats(Box::new(error)))?;
    if marker.is_none() && !needs_rewind {
        return Ok(());
    }
    let marker_height = marker.as_ref().map_or(head.height, |m| m.height);
    let marker_hash = marker.as_ref().map_or(head.tip, |m| m.hash);
    tracing::warn!(
        height = marker_height,
        hash = %marker_hash,
        head = %head.tip,
        head_height = head.height,
        mode,
        "automatic disconnect recovery replayed the certified head chain"
    );
    if let Err(error) = handles.publish_recovery_checkpoint() {
        return Err(ApplyError::RecoveryPublication(Box::new(error)));
    }
    Ok(())
}

struct HeadChainAnchor {
    pub(super) anchor_height: u32,
    pub(super) anchor: Hash256,
    pub(super) above: Vec<(u32, Hash256)>,
}

impl HeadChainAnchor {
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
        let block: Block = bitcoin_rs_consensus::primitives::deserialize(&bytes)
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

fn rewind_refused(handles: &Chainstate, head: &DurableHead, reason: &'static str) -> ApplyError {
    gap_unrecoverable(head, handles.applied_tip.load_full().as_deref(), reason)
}

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
    let block: Block = bitcoin_rs_consensus::primitives::deserialize(&bytes)
        .map_err(|_| rewind_refused(handles, head, "a rewound block body does not decode"))?;
    if block.block_hash().0 != hash {
        return Err(rewind_refused(
            handles,
            head,
            "a rewound block body does not hash to the applied tip",
        ));
    }
    let txids: Vec<bitcoin_rs_consensus::primitives::Txid> = block
        .txs
        .iter()
        .map(bitcoin_rs_consensus::primitives::Tx::txid)
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
    let coin_delta = super::disconnect::build_disconnect_delta(&handles.coins, &undo)
        .map_err(|_| rewind_refused(handles, head, "failed to compute coin delta for rewind"))?;
    handles
        .coin_stats
        .check_rewind(height, tx_count_delta)
        .map_err(|_| {
            rewind_refused(
                handles,
                head,
                "the coin statistics refused the rewind to the durable head",
            )
        })?;
    handles
        .coin_stats
        .rewind_block(height, parent_tip.height, tx_count_delta)
        .map_err(|_| {
            rewind_refused(
                handles,
                head,
                "the coin statistics refused the rewind to the durable head",
            )
        })?;
    handles
        .commit_authority
        .rewind_coins(&coin_delta)
        .map_err(|_| rewind_refused(handles, head, "failed to persist coin rewind"))?;
    handles.publish_applied(&parent_tip, crate::events::HintKind::Disconnected);
    Ok(())
}

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

fn replay_committed_gap(
    handles: &Chainstate,
    head: &DurableHead,
    restored: Option<&TipSnapshot>,
) -> Result<(), ApplyError> {
    let unrecoverable = |reason: &'static str| gap_unrecoverable(head, restored, reason);
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
    let gap_width = usize::try_from(head.height - base_height + 1)
        .map_err(|_| unrecoverable("gap width exceeds the address space"))?;

    let Some(store) = handles.block_body_store.as_ref() else {
        return Err(unrecoverable("no block body store is attached"));
    };
    let load_body = |height: u32, hash: Hash256| -> Result<BlockImage, ApplyError> {
        let bytes = store
            .load_block_body(height, hash)
            .map_err(ApplyError::BlockBodyPersistence)?
            .ok_or_else(|| unrecoverable("a committed gap body is missing from storage"))?;
        let payload = BlockImage::from_raw(bytes::Bytes::from(bytes))
            .map_err(|_| unrecoverable("a committed gap body does not decode"))?;
        if payload.block_hash().0 != hash {
            return Err(unrecoverable(
                "a stored body does not hash to its committed hash",
            ));
        }
        Ok(payload)
    };

    let mut chain = Vec::with_capacity(gap_width);
    let mut cursor = (head.height, head.tip);
    loop {
        let payload = load_body(cursor.0, cursor.1)?;
        let parent = payload.header().prev_blockhash.0;
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

fn apply_replayed_gap_block(
    handles: &Chainstate,
    head: &DurableHead,
    restored: Option<&TipSnapshot>,
    payload: &BlockImage,
    height: u32,
    hash: Hash256,
) -> Result<super::ConnectOutcome, ApplyError> {
    let proven = match load_block_undo(handles.undo_store.as_ref(), height, hash) {
        Ok(undo) if restored.is_some() => Some(ProvenApply::AssumeValidSkipped(
            super::prepare::prepare_apply(
                payload,
                &UndoRowSpends(&undo),
                handles.validation_engine,
            )?,
        )),
        Ok(_) | Err(UndoLoadError::Missing { .. }) => None,
        Err(_) => {
            return Err(ApplyError::DurableHeadGapUnrecoverable {
                head_tip: head.tip,
                head_height: head.height,
                restored_tip: restored.map(|tip| tip.hash),
                restored_height: restored.map(|tip| tip.height),
                reason: "a committed gap undo record does not load",
            });
        }
    };
    let replay_token = ReplayToken(());
    super::connect::apply_committed_block_admitted(
        handles,
        payload,
        proven,
        super::connect::ApplyScope {
            provenance: if restored.is_none() {
                BlockProvenance::ColdReplay(replay_token)
            } else {
                BlockProvenance::LocalReplay(replay_token)
            },
            staged: None,
        },
        PublishMode::Replay {
            receipt: DurableReceipt::from_head(head),
            certify_head: height == head.height && hash == head.tip,
        },
    )
}

/// Any failure leaves the fence closed rather than half-served.
///
/// The gap blocks re-apply idempotently on the next boot — their durable facts are
/// unchanged — so a failed replay stays exactly the gap it started as, and the next
/// restart retries it from the same durable state.
fn replay_gap_chain(
    handles: &Chainstate,
    head: &DurableHead,
    chain: Vec<(u32, Hash256)>,
    restored: Option<&TipSnapshot>,
    load_body: impl Fn(u32, Hash256) -> Result<BlockImage, ApplyError>,
) -> Result<(), ApplyError> {
    let unrecoverable = |reason: &'static str| gap_unrecoverable(head, restored, reason);
    let transition = Some(handles.begin_transition()?);
    let replayed_blocks = u64::try_from(chain.len()).unwrap_or(u64::MAX);
    let replayed = (|| {
        let mut commit_id = 0_u64;
        for (height, hash) in chain {
            let payload = load_body(height, hash)?;
            let outcome =
                apply_replayed_gap_block(handles, head, restored, &payload, height, hash)?;
            commit_id = outcome.commit_id;
            tracing::debug!(height, hash = %hash.to_string_be(), "replayed committed gap block");
        }
        let published = handles.applied_tip.load_full();
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
        if restored.is_none() {
            handles
                .durable_head
                .attest(head, bitcoin_rs_storage::ScriptAttestation::Full)
                .map_err(ApplyError::DurableHeadCommit)?;
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
mod tests;
