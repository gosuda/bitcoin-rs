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
use super::BlockProvenance;
use super::Chainstate;
use super::ProvenApply;
use super::PublishMode;
use super::error::ApplyError;
use bitcoin_rs_chain::{ChainTxCount, TipSnapshot};
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_storage::{CommitRecords, DurableHead};
use bitcoin_rs_utxo::{LiveOutput, OutputSource, UndoLoadError, load_block_undo};

/// What one durable head commit certified.
///
/// PRE: a receipt comes only from a successful durable connect or disconnect
/// commit, or from reconstructing the already committed head during replay.
///
/// POST: it names the durable commit id and the exact cumulative chain
/// transaction count that publication may carry.
///
/// INVARIANT: publication cannot accept a bare commit id or count that a
/// commit did not name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DurableReceipt {
    /// The `DurableHead::commit_id` the batch assigned.
    pub(super) commit_id: u64,
    /// The cumulative chain transaction count the batch named.
    pub(super) chain_tx_count: ChainTxCount,
}

impl DurableReceipt {
    /// The receipt of an already committed head, as crash recovery reads it
    /// back. Replay never mints a commit: it republishes under this receipt.
    pub(super) fn from_head(head: &DurableHead) -> Self {
        Self {
            commit_id: head.commit_id,
            chain_tx_count: ChainTxCount::from_wire(head.chain_tx_count),
        }
    }

    /// The applied tip this receipt certifies: `tip` with the committed count.
    pub(super) fn certify(self, mut tip: TipSnapshot) -> TipSnapshot {
        tip.chain_tx_count = self.chain_tx_count;
        tip
    }
}

/// Facts of one connected block that its durable head commit names.
pub(super) struct ConnectCommitFacts {
    /// Parent the durable head must currently name — for a group, the
    /// parent of its first block. A stored head naming any other tip means
    /// the durable chain and the in-memory chain have diverged (a crash
    /// landed the batch but not the publication, and recovery has not
    /// replayed the gap yet): refuse rather than advance a head whose
    /// lineage would break.
    pub prev_hash: Hash256,
    /// The prefix tip this commit certifies.
    pub tip: Hash256,
    /// Height of `tip`.
    pub height: u32,
    /// Cumulative chain transaction count at `tip`, matching what
    /// publication will store.
    pub chain_tx_count_after: u64,
    /// The newest undo row `(height, hash)` this commit certifies: a
    /// connect or group names its last block, a disconnect keeps the prior
    /// extent.
    pub undo_extent: Option<(u32, Hash256)>,
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
    store.sync().map_err(ApplyError::DurableHeadCommit)
}

/// Advances the durable head for one connected block.
///
/// Returns the [`DurableReceipt`] the batch issued: the commit id it assigned
/// and the count it named, which is all publication may carry. The first
/// commit on a datadir fences on absence; every later commit fences on the
/// encoded previous head, which makes the transition lock's single-writer
/// guarantee checkable on disk and keeps `commit_id` strictly monotonic
/// (`P3`).
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
///
/// A disconnect commits too: the head moves to the parent tip with the next
/// `commit_id`, so a reorg may lower `height` but never `commit_id` (`P3`).
/// The returned receipt names that id and the parent count the batch wrote.
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

/// Resolves one replayed block's spends from its own durable undo row.
///
/// The stored head certifies the undo record in the same batch as the body,
/// so the coins it restores are exactly the inputs the committed block saw.
struct UndoRowSpends<'a>(&'a bitcoin_rs_utxo::UndoBatch);

impl OutputSource for UndoRowSpends<'_> {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<LiveOutput> {
        self.0
            .restores()
            .iter()
            .find(|add| &add.outpoint == outpoint)
            .map(|add| LiveOutput {
                txout: add.txout.clone(),
                coinbase: add.coinbase,
                height: add.height,
            })
    }
}

/// Boot-time reconciliation of the stored head against the restored tip.
///
/// An unreadable head fails startup (`P5`: corruption inside the commit
/// point never degrades silently). A head ahead of the restored tip names a
/// committed-but-unpublished gap: the crash landed the batch but not the
/// publication. The internal replay path walks the durable bodies down from
/// the stored tip, re-applies them through the ordinary commit path with the
/// head suppressed, and publishes — so ordinary operation never starts on a
/// state the head does not certify. A gap that is not an ancestor prefix of
/// stored bodies fails closed: no partial success publishes.
///
/// Coins are durable only through the checkpoint export, so a head with no
/// restored chainstate — a crash before the first clean checkpoint, or a
/// forced full revalidation — is the same gap measured from the empty chain:
/// the head certifies the bodies, and replaying them from genesis rebuilds
/// exactly the state it names.
///
/// Recoverability is defined by the identity and ancestry checks the replay
/// performs, never by gap width. Any authenticated ancestor chain above the
/// restored tip replays, however wide; a gap that is not an ancestor prefix
/// of stored bodies fails closed.
pub fn reconcile_at_boot(handles: &Chainstate) -> Result<(), ApplyError> {
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
///
/// With no marker this is ordinary durable-head reconciliation
/// ([`reconcile_at_boot`]) unchanged. A marker is recovery evidence, not a
/// permanent operator refusal. Every checkpoint is written atomically and
/// the publisher refuses a tip the head has not certified, so the restored
/// state is self-consistent but possibly stale: it sits on the certified
/// chain below the durable head — the same publication lag any crash
/// leaves — or already at it. What the marker records is a branch decision
/// whose consequences may exist only in memory. Recovery therefore replays
/// the certified head chain onto the restored state, warns with the marker
/// identity, publishes a clean checkpoint, and retires the marker only
/// after that publication is durable.
///
/// PRE: the chainstate is restored; no network or worker can observe it
/// yet.
///
/// POST: success has a coherent applied tip at the durable head, has
/// warned for marker recovery, and has retired the marker after durable
/// publication.
///
/// INVARIANT: marker presence never authorizes a partially reconstructed
/// state. An unreadable marker or head, or a restored state that does not
/// sit below an authenticated head, fails closed with the existing
/// recovery error and retains the marker.
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
    // The same walk that closes an ordinary publication lag: it replays the
    // certified head chain onto the restored state or fails closed when the
    // restored state does not sit below that head — divergence, not lag.
    reconcile_at_boot(handles)?;
    tracing::warn!(
        height = marker.height,
        hash = %marker.hash,
        head = %head.tip,
        head_height = head.height,
        head_still_certifies_tip = head.tip == marker.hash,
        "automatic disconnect recovery replayed the certified head chain"
    );
    // Publication is the durability fence: the marker retires only after the
    // repaired state lands in a clean checkpoint. A failure retains it.
    if let Err(error) = handles.publish_recovery_checkpoint() {
        return Err(ApplyError::RecoveryPublication(Box::new(error)));
    }
    handles
        .undo_store
        .retire_disconnect_marker()
        .map_err(|error| {
            tracing::error!(%error, "disconnect marker retirement failed after publication");
            fail_closed(
                head.tip,
                head.height,
                "the disconnect marker did not retire after recovery publication",
            )
        })
}

/// Replays the committed-but-unpublished gap onto the restored chainstate.
///
/// Replays every authenticated durable-head body above `restored`, or the
/// complete certified head chain when `restored` is `None`.
///
/// # Errors
///
/// The first body that is missing from storage, does not hash to the stored
/// head identity, or does not descend from the stored tip fails startup
/// closed: no partial success publishes.
///
/// # PRE
///
/// The stored head is loaded successfully and every body it names exists,
/// and every body equals the committed hash.
///
/// # POST
///
/// Success publishes exactly `head.tip`, `head.height`, and
/// `head.commit_id`; failure leaves admission closed and publishes no
/// guess.
///
/// # INVARIANT
///
/// Body identity, ancestry, durable receipt, and publication order are
/// checked. The walk is durable-resolved: the stored head names the tip,
/// every step loads `(height, hash)` by the parent chain the previous body
/// names, and peak retained state is one block plus the hash descriptors.
/// Each block re-enters through [`PublishMode::Replay`], which redoes the
/// derived work publication owed — coins, bookkeeping, journal tail, tip —
/// under the receipt the head already issued, and never re-commits the head:
/// `commit_id` stays exactly the stored one (`P3`).
fn replay_committed_gap(
    handles: &Chainstate,
    head: DurableHead,
    restored: Option<&TipSnapshot>,
) -> Result<(), ApplyError> {
    let unrecoverable = |reason: &'static str| ApplyError::DurableHeadGapUnrecoverable {
        head_tip: head.tip,
        head_height: head.height,
        restored_tip: restored.map(|tip| tip.hash),
        restored_height: restored.map(|tip| tip.height),
        reason,
    };
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
    // Width bounds the descriptor allocation only. Recoverability is decided
    // by the body-identity and ancestry checks below, never by how wide the
    // gap is: any authenticated ancestor chain above the restored tip
    // replays, however many commit groups it spans.
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
    // Each body loads once to learn its parent and once more during replay,
    // so peak retained bytes stay at one block.
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
///
/// One transition across the gap: the replay is recovery itself, so a
/// failure must leave the fence closed rather than half-served. The gap
/// blocks re-apply idempotently on the next boot — their durable facts
/// are unchanged — so a failed replay stays exactly the gap it started
/// as, and the next restart retries it from the same durable state.
fn replay_gap_chain(
    handles: &Chainstate,
    head: DurableHead,
    chain: Vec<(u32, Hash256)>,
    restored: Option<&TipSnapshot>,
    load_body: impl Fn(u32, Hash256) -> Result<(Block, Vec<u8>), ApplyError>,
) -> Result<(), ApplyError> {
    let unrecoverable = |reason: &'static str| ApplyError::DurableHeadGapUnrecoverable {
        head_tip: head.tip,
        head_height: head.height,
        restored_tip: restored.map(|tip| tip.hash),
        restored_height: restored.map(|tip| tip.height),
        reason,
    };
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
        let landed = published.as_ref().is_some_and(|tip| {
            (
                tip.hash,
                tip.height,
                tip.chain_tx_count.to_wire(),
                commit_id,
            ) == (head.tip, head.height, head.chain_tx_count, head.commit_id)
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
