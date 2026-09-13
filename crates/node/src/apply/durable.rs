//! The ordered durable commit between chain mutation and publication.
//!
//! `RCV-02` orders every connect as: reserve, append, sync, one atomic
//! durable batch, publish. The apply path already reserves (admission +
//! transition lock), appends (deferred undo row, flat-file body, deferred
//! locator rows), and commits the UTXO set in memory. This module owns what
//! was missing: the sync that certifies those bytes, and the
//! [`DurableHead`] batch that names them — the chain's durable commit point.
//!
//! After [`commit_connect_head`] returns `Ok`, the block is durable as one
//! unit: head, undo record, and body locator in a single `write_durable_if`
//! receipt, with body bytes and the blocks directory synced before the batch
//! could name them (`INV-06`). Publication happens strictly after, so a
//! follower-visible tip is always already durable (`INV-04`), and a crash
//! recovers either the old committed head or the new one — never a mix.
//!
//! `Err` from the batch is not a rollback receipt: the batch may have applied
//! before durability completion failed. Like a `UtxoCommit` refusal, the
//! caller must not retry the block; recovery owns the reconciliation.

use super::Chainstate;
use super::error::ApplyError;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{CommitRecords, DurableHead};

/// Facts of one connected block that its durable head commit names.
pub(super) struct ConnectCommitFacts<'a> {
    /// Parent the durable head must currently name. A stored head naming any
    /// other tip means the durable chain and the in-memory chain have
    /// diverged (a crash landed the batch but not the publication, and
    /// recovery has not replayed the gap yet): refuse rather than advance a
    /// head whose lineage would break.
    pub prev_hash: Hash256,
    /// The block's hash: the tip this commit certifies.
    pub tip: Hash256,
    /// Height of `tip`.
    pub height: u32,
    /// The block's encoded undo record, landed in the same receipt.
    pub undo_record: &'a [u8],
    /// Cumulative chain transaction count after this block, matching what
    /// publication will store.
    pub chain_tx_count_after: u64,
}

/// Makes the appended block data durable before the head may name it.
///
/// Syncs the flat block files (data + directory) and flushes the key-value
/// index, so every deferred locator row and the deferred undo row are on
/// disk when the batch runs. `P1` rests on this ordering: the head commit
/// never precedes the durability of the ranges it names.
pub(super) fn sync_appended_blocks(handles: &Chainstate) -> Result<(), ApplyError> {
    let Some(store) = handles.block_body_store.as_ref() else {
        return Ok(());
    };
    store.sync().map_err(ApplyError::BlockBodyPersistence)
}

/// Advances the durable head for one connected block.
///
/// Returns the commit id the batch assigned. The first commit on a datadir
/// fences on absence; every later commit fences on the encoded previous
/// head, which makes the transition lock's single-writer guarantee checkable
/// on disk and keeps `commit_id` strictly monotonic (`P3`).
pub(super) fn commit_connect_head(
    handles: &Chainstate,
    facts: &ConnectCommitFacts<'_>,
) -> Result<u64, ApplyError> {
    let prior = handles
        .durable_head
        .load()
        .map_err(ApplyError::DurableHeadCommit)?;
    if let Some(head) = prior.as_ref()
        && head.tip != facts.prev_hash
    {
        return Err(ApplyError::DurableHeadLineage {
            head: head.tip,
            prev: facts.prev_hash,
        });
    }
    let body_rows = match handles.block_body_store.as_ref() {
        Some(store) => {
            let position = store
                .block_position(facts.height, facts.tip)
                .map_err(ApplyError::BlockBodyPersistence)?;
            position
                .map(|position| vec![(facts.height, facts.tip, position)])
                .unwrap_or_default()
        }
        None => Vec::new(),
    };
    let next = DurableHead {
        commit_id: prior.as_ref().map_or(1, |head| head.commit_id + 1),
        height: facts.height,
        tip: facts.tip,
        chain_tx_count: facts.chain_tx_count_after,
        body_extent: handles
            .block_body_store
            .as_ref()
            .and_then(|store| store.append_cursor()),
        undo_extent: Some((facts.height, facts.tip)),
    };
    let records = CommitRecords {
        undo_rows: vec![(facts.height, facts.tip, facts.undo_record)],
        body_rows,
    };
    handles
        .durable_head
        .commit(prior.as_ref(), &next, &records)
        .map_err(ApplyError::DurableHeadCommit)?;
    metrics::counter!("node.durable_head.commits").increment(1);
    Ok(next.commit_id)
}

/// Advances the durable head for one disconnected block.
///
/// A disconnect commits too: the head moves to the parent tip with the next
/// `commit_id`, so a reorg may lower `height` but never `commit_id` (`P3`).
/// The extents stay as the previous head certified them — a disconnect
/// appends nothing, and the disconnected block's undo row stays durable for
/// a possible reconnect. The stored head must name exactly the block being
/// disconnected; any other tip is the divergence `DurableHeadLineage`
/// refuses.
pub(super) fn commit_disconnect_head(
    handles: &Chainstate,
    parent_tip: &bitcoin_rs_chain::TipSnapshot,
    disconnected_hash: Hash256,
    chain_tx_count_after: u64,
) -> Result<u64, ApplyError> {
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
    Ok(next.commit_id)
}

/// Boot-time reconciliation of the stored head against the restored tip.
///
/// An unreadable head fails startup (`P5`: corruption inside the commit
/// point never degrades silently). A head that is ahead of the restored tip
/// names a committed-but-unpublished gap: the crash landed between the batch
/// and the publication. Recovery that can replay the gap is issue #655; for
/// now the gap is surfaced as a typed warning and counted, and the first
/// connect refuses via [`ApplyError::DurableHeadLineage`] rather than
/// advancing a head whose lineage would break.
pub(crate) fn reconcile_at_boot(handles: &Chainstate) -> Result<(), ApplyError> {
    let stored = handles
        .durable_head
        .load()
        .map_err(ApplyError::DurableHeadCommit)?;
    let Some(head) = stored else {
        return Ok(());
    };
    let Some(tip) = handles.applied_tip.load_full() else {
        tracing::warn!(
            head_height = head.height,
            head_tip = %head.tip.to_string_be(),
            "durable head exists but no chainstate was restored"
        );
        return Ok(());
    };
    if tip.hash != head.tip {
        metrics::counter!("node.durable_head.recovery_gaps").increment(1);
        tracing::warn!(
            head_height = head.height,
            head_tip = %head.tip.to_string_be(),
            restored_height = tip.height,
            restored_tip = %tip.hash.to_string_be(),
            "restored tip is behind the durable head; the gap is committed and awaits replay"
        );
    }
    Ok(())
}
