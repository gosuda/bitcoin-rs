use super::error::ApplyError;
use super::tx_count_delta_for;
use super::{BlockProvenance, Chainstate, ProvenApply, PublishMode};
use crate::chain::{ChainTxCount, TipSnapshot};
use bitcoin_rs_consensus::primitives::{Block, BlockImage, Hash256, OutPoint};
use bitcoin_rs_storage::DurableHead;
use bitcoin_rs_storage::utxo::UtxoCoin;
use bitcoin_rs_storage::utxo::contract::{
    BlockUndoCheck, OutputSource, UndoLoadError, load_block_undo, load_block_undo_for_block,
};

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
    let undo = load_block_undo_for_block(
        handles.undo_store.as_ref(),
        height,
        hash,
        &BlockUndoCheck {
            block: &block,
            txids: &txids,
            max_script_size: bitcoin_rs_consensus::MAX_SCRIPT_SIZE,
        },
    )
    .map_err(|_| {
        rewind_refused(
            handles,
            head,
            "a rewound block's undo record does not load or does not match the block",
        )
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
                handles.prevout_charge.clone(),
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
mod tests {
    use crate::chain::current_unix_seconds;
    use crate::chain::regtest_fixture::mined_regtest_child_at as mined_child;
    use bitcoin_rs_consensus::primitives::{
        Block, BlockHash, BlockImage, Hash256, Network, OutPoint, consensus_bytes,
    };
    use bitcoin_rs_storage::block_body::BlockBodyStore;
    use bitcoin_rs_storage::utxo::UtxoSet;
    use bitcoin_rs_storage::utxo::record::UtxoRecord;
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
    use bitcoin_rs_storage::{
        CoinKey, ColumnFamily, CommitRecords, DurableHead, DurableHeadStore,
        InMemoryDurableHeadStore, KvStore, StorageError,
    };
    use parking_lot::Mutex;
    use proptest::prelude::*;
    use std::sync::Arc;

    use crate::test_fixtures::{TestError, TestResult, handles, handles_with_store, seed_genesis};
    use crate::test_support::MemoryBodies;
    use crate::{ApplyError, Chainstate};

    mod revalidation {
        use std::path::Path;
        use std::sync::Arc;

        use super::*;
        use crate::{
            ValidationMode,
            recovery::{
                ResumeSource, install_restored_state, prepare_initial_chainstate,
                prepare_initial_state_with_engine, require_full_script_attestation,
                requires_full_revalidation,
            },
        };
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockHash, BlockImage, LockTime, Network, OutPoint, Sequence, Tx, TxIn,
            TxOut, Witness, consensus_bytes,
        };
        use bitcoin_rs_consensus::script::{
            VerifyFlags,
            opcode::{OP_PUSHNUM_1, OP_RETURN},
        };
        use bitcoin_rs_consensus::{ConsensusError, ValidationEngine};
        use bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER;

        use crate::test_fixtures::{TestError, TestResult};

        struct SpendView(OutPoint, TxOut);

        impl bitcoin_rs_consensus::UtxoView for SpendView {
            fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
                (*outpoint == self.0).then(|| self.1.clone())
            }
        }

        fn write_accepted_checkpoint(dir: &Path, chain: &Chainstate) -> TestResult {
            let store = bitcoin_rs_storage::checkpoint::open_data_dir(dir)?;
            let config = crate::checkpoint::headers::HeaderCheckpointConfig {
                network: Network::Regtest,
                genesis: Network::Regtest.genesis_block_hash(),
            };
            let engine = chain.commit_authority.store().clone();
            crate::checkpoint::write_checkpoint_with_store(
                &store,
                config,
                &chain.block_tree,
                &chain.coin_stats,
                chain.applied_tip_snapshot().as_deref(),
                crate::checkpoint::CheckpointStoreTarget {
                    store: engine.as_ref(),
                    host_data_dir: dir,
                },
            )?;
            Ok(())
        }

        fn chain_at_height_100() -> TestResult<(Chainstate, OutPoint, TxOut, BlockHash)> {
            let (mut chain, first) = restored_chainstate()?;
            let bodies = Arc::new(MemoryBodies::default());
            let genesis = Network::Regtest.genesis_block();
            bodies.persist_block_body(0, genesis.block_hash().0, &consensus_bytes(&genesis))?;
            chain.block_body_store = Some(bodies);
            chain.apply_block(&BlockImage::from_local(first.clone()))?;
            let funding = OutPoint::new(first.txs[0].txid(), 0);
            let funding_output = first.txs[0].outputs[0].clone();
            let mut parent = first.block_hash();
            for height in 2..=100 {
                let child = mined_child(parent, height)?;
                chain.apply_block(&BlockImage::from_local(child.clone()))?;
                parent = child.block_hash();
            }
            Ok((chain, funding, funding_output, parent))
        }
        fn commit_chain(
            opcode: u8,
        ) -> TestResult<(Chainstate, Block, OutPoint, Option<tempfile::TempDir>)> {
            let (chain, funding, funding_output, parent) = chain_at_height_100()?;
            commit_spent_script(chain, funding, funding_output, parent, opcode, None)
        }
        fn commit_chain_with_checkpoint(
            opcode: u8,
        ) -> TestResult<(Chainstate, Block, OutPoint, tempfile::TempDir)> {
            let (chain, funding, funding_output, parent) = chain_at_height_100()?;
            let checkpoint_dir = tempfile::tempdir()?;
            crate::events::initialize_data_dir(checkpoint_dir.path())?;
            write_accepted_checkpoint(checkpoint_dir.path(), &chain)?;
            let (chain, block, funding, checkpoint_dir) = commit_spent_script(
                chain,
                funding,
                funding_output,
                parent,
                opcode,
                Some(checkpoint_dir),
            )?;
            let checkpoint_dir = checkpoint_dir.ok_or(TestError::UnexpectedSuccess(
                "the accepted checkpoint directory must survive the commit",
            ))?;
            Ok((chain, block, funding, checkpoint_dir))
        }
        fn commit_spent_script(
            mut chain: Chainstate,
            funding: OutPoint,
            funding_output: TxOut,
            parent: BlockHash,
            opcode: u8,
            checkpoint_dir: Option<tempfile::TempDir>,
        ) -> TestResult<(Chainstate, Block, OutPoint, Option<tempfile::TempDir>)> {
            let mut spend_block = mined_child(parent, 101)?;
            let spend = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: funding,
                    script_sig: vec![opcode].into(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: vec![OP_PUSHNUM_1].into(),
                }],
                lock_time: LockTime::ZERO,
            };
            let verdict = bitcoin_rs_consensus::verify_transaction(
                &spend,
                &SpendView(funding, funding_output),
                101,
                0,
                VerifyFlags::MANDATORY,
                ValidationEngine::Native,
                None,
            );
            if opcode == OP_RETURN {
                assert!(matches!(verdict, Err(ConsensusError::Script { .. })));
            } else {
                verdict?;
            }
            spend_block.txs.push(spend);
            spend_block.header.merkle_root =
                crate::chain::regtest_fixture::merkle_root(&spend_block.txs)
                    .ok_or(TestError::Missing("missing merkle root"))?;
            crate::chain::regtest_fixture::mine_block_to_declared_target(&mut spend_block)?;
            let successor = mined_child(spend_block.block_hash(), 102)?;
            chain.admit_headers(&[spend_block.header, successor.header])?;
            chain.validation_mode = ValidationMode::AssumeValid;
            chain.assume_valid_height = 102;
            chain.assume_valid_gate = std::sync::Arc::new(crate::AssumeValidGate::with_anchor(
                Some((102, successor.block_hash().0)),
            ));
            chain.assume_valid_gate.evaluate(&chain.block_tree.read());
            chain.apply_block(&BlockImage::from_local(spend_block.clone()))?;
            chain.apply_block(&BlockImage::from_local(successor))?;
            Ok((chain, spend_block, funding, checkpoint_dir))
        }

        const FULL_REVALIDATION_MARKER_TEXT: &[u8] =
            b"full revalidation required after the checkpoint base\n";

        fn write_full_revalidation_marker(dir: &Path, marker: &[u8]) -> TestResult {
            std::fs::write(dir.join(FULL_REVALIDATION_MARKER), marker)?;
            Ok(())
        }

        fn prepare_cold(
            chain: &mut Chainstate,
            checkpoint_dir: Option<tempfile::TempDir>,
            mode: ValidationMode,
        ) -> TestResult<tempfile::TempDir> {
            prepare_cold_with_optional_marker(chain, checkpoint_dir, mode, None)
        }

        fn prepare_cold_with_marker(
            chain: &mut Chainstate,
            checkpoint_dir: Option<tempfile::TempDir>,
            mode: ValidationMode,
        ) -> TestResult<tempfile::TempDir> {
            prepare_cold_with_optional_marker(
                chain,
                checkpoint_dir,
                mode,
                Some(FULL_REVALIDATION_MARKER_TEXT),
            )
        }

        fn prepare_cold_with_optional_marker(
            chain: &mut Chainstate,
            checkpoint_dir: Option<tempfile::TempDir>,
            mode: ValidationMode,
            marker: Option<&[u8]>,
        ) -> TestResult<tempfile::TempDir> {
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing durable head"))?;
            let dir = if let Some(dir) = checkpoint_dir {
                if let Some(marker) = marker {
                    let baseline = prepare_initial_chainstate(
                        dir.path(),
                        Network::Regtest,
                        Some(&head),
                        None,
                    )?;
                    assert_eq!(baseline.resume_source, ResumeSource::Checkpoint);
                    assert_eq!(baseline.applied_tip.as_ref().map(|t| t.height), Some(100));
                    write_full_revalidation_marker(dir.path(), marker)?;
                }
                dir
            } else {
                let dir = tempfile::tempdir()?;
                crate::events::initialize_data_dir(dir.path())?;
                if let Some(marker) = marker {
                    write_full_revalidation_marker(dir.path(), marker)?;
                }
                dir
            };
            let restored =
                prepare_initial_state_with_engine(dir.path(), Network::Regtest, Some(&head), None)?;
            assert_eq!(restored.initial.resume_source, ResumeSource::Cold);
            assert!(restored.initial.applied_tip.is_none());
            install_restored_state(chain, restored, mode)?;
            Ok(dir)
        }

        fn prepare_warm(
            chain: &mut Chainstate,
            checkpoint_dir: tempfile::TempDir,
            mode: ValidationMode,
        ) -> TestResult<tempfile::TempDir> {
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing durable head"))?;
            let restored = prepare_initial_state_with_engine(
                checkpoint_dir.path(),
                Network::Regtest,
                Some(&head),
                None,
            )?;
            assert_eq!(restored.initial.resume_source, ResumeSource::Checkpoint);
            let tip = restored
                .initial
                .applied_tip
                .clone()
                .ok_or(TestError::Missing("missing checkpoint tip"))?;
            assert_eq!(tip.height, 100);
            install_restored_state(chain, restored, mode)?;
            Ok(checkpoint_dir)
        }

        #[test]
        fn cold_revalidation_rejects_script_invalid_commits_and_preserves_recovery_evidence()
        -> TestResult {
            for mode in [ValidationMode::Full, ValidationMode::AssumeValid] {
                for marker in [false, true] {
                    let (mut chain, invalid, funding, checkpoint_dir) = if marker {
                        let (chain, invalid, funding, checkpoint_dir) =
                            commit_chain_with_checkpoint(OP_RETURN)?;
                        (chain, invalid, funding, Some(checkpoint_dir))
                    } else {
                        commit_chain(OP_RETURN)?
                    };
                    let head = chain.durable_head.load()?;
                    let hash = invalid.block_hash().0;
                    let undo = chain.undo_store.load_undo(101, hash)?;
                    let dir = if marker {
                        prepare_cold_with_marker(&mut chain, checkpoint_dir, mode)?
                    } else {
                        prepare_cold(&mut chain, checkpoint_dir, mode)?
                    };
                    let error = super::super::reconcile_at_boot(&chain)
                        .err()
                        .ok_or(TestError::Missing("a cold rebuild must verify scripts"))?;
                    assert!(
                        matches!(error, ApplyError::Consensus(ConsensusError::Script { .. })),
                        "{error:?}"
                    );
                    let tip = chain
                        .applied_tip_snapshot()
                        .ok_or(TestError::Missing("missing replay prefix"))?;
                    assert_eq!(
                        (tip.height, tip.hash),
                        (100, invalid.header.prev_blockhash.0)
                    );
                    assert_eq!(chain.chain_snapshot().tip_hash, tip.hash);
                    assert_eq!(chain.chain_snapshot().tip_height, 100);
                    assert_eq!(chain.coin_stats.snapshot().height, 100);
                    assert!(chain.utxo_reader().get(&funding)?.is_some());
                    assert!(
                        chain
                            .utxo_reader()
                            .get(&OutPoint::new(invalid.txs[1].txid(), 0))?
                            .is_none()
                    );
                    assert_eq!(chain.durable_head.load()?, head);
                    assert_eq!(chain.undo_store.load_undo(101, hash)?, undo);
                    assert_eq!(
                        chain
                            .block_body_store
                            .as_ref()
                            .ok_or(TestError::Missing("missing body store"))?
                            .load_block_body(101, hash)?,
                        Some(consensus_bytes(&invalid))
                    );
                    assert!(matches!(
                        chain.begin_transition(),
                        Err(ApplyError::Shutdown)
                    ));
                    if marker {
                        assert_eq!(
                            std::fs::read(dir.path().join(FULL_REVALIDATION_MARKER))?,
                            b"full revalidation required after the checkpoint base\n"
                        );
                    }
                }
            }
            Ok(())
        }

        #[test]
        fn valid_cold_revalidation_reuses_the_durable_receipt() -> TestResult {
            for marker in [false, true] {
                let (mut chain, valid, funding, checkpoint_dir) = if marker {
                    let (chain, valid, funding, checkpoint_dir) =
                        commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
                    (chain, valid, funding, Some(checkpoint_dir))
                } else {
                    commit_chain(OP_PUSHNUM_1)?
                };
                let head = chain
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("missing durable head"))?;
                let dir = if marker {
                    prepare_cold_with_marker(&mut chain, checkpoint_dir, ValidationMode::Full)?
                } else {
                    prepare_cold(&mut chain, checkpoint_dir, ValidationMode::Full)?
                };
                super::super::reconcile_at_boot(&chain)?;
                let tip = chain
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("missing replay tip"))?;
                assert_eq!((tip.height, tip.hash), (head.height, head.tip));
                assert_eq!(tip.chain_tx_count.to_wire(), head.chain_tx_count);
                assert_eq!(chain.durable_head.load()?, Some(head));
                assert_eq!(chain.chain_snapshot().tip_hash, head.tip);
                assert!(chain.utxo_reader().get(&funding)?.is_none());
                assert!(
                    chain
                        .utxo_reader()
                        .get(&OutPoint::new(valid.txs[1].txid(), 0))?
                        .is_some()
                );
                assert!(chain.begin_transition().is_ok());
                assert_eq!(
                    crate::recovery::requires_full_revalidation(dir.path()),
                    marker
                );
            }
            Ok(())
        }

        #[test]
        fn cold_revalidation_still_refuses_corrupt_undo_instead_of_replacing_it() -> TestResult {
            let (mut chain, valid, _, checkpoint_dir) = commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
            let head = chain.durable_head.load()?;
            let hash = valid.block_hash().0;
            chain.undo_store.persist_undo(101, hash, b"corrupt")?;
            let dir =
                prepare_cold_with_marker(&mut chain, Some(checkpoint_dir), ValidationMode::Full)?;
            let error = super::super::reconcile_at_boot(&chain)
                .err()
                .ok_or(TestError::Missing("corrupt undo must fail closed"))?;
            assert!(matches!(
                error,
                ApplyError::DurableHeadGapUnrecoverable { .. }
            ));
            assert_eq!(chain.durable_head.load()?, head);
            assert_eq!(
                chain.undo_store.load_undo(101, hash)?,
                Some(b"corrupt".to_vec())
            );
            assert!(crate::recovery::requires_full_revalidation(dir.path()));
            assert!(matches!(
                chain.begin_transition(),
                Err(ApplyError::Shutdown)
            ));
            Ok(())
        }

        #[test]
        fn valid_warm_revalidation_reuses_the_durable_receipt_and_undo_preparation() -> TestResult {
            let (mut chain, valid, funding, checkpoint_dir) =
                commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing durable head"))?;
            let _dir = prepare_warm(&mut chain, checkpoint_dir, ValidationMode::Full)?;
            super::super::reconcile_at_boot(&chain)?;
            let tip = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing replay tip"))?;
            assert_eq!((tip.height, tip.hash), (head.height, head.tip));
            assert_eq!(tip.chain_tx_count.to_wire(), head.chain_tx_count);
            assert_eq!(chain.durable_head.load()?, Some(head));
            assert_eq!(chain.chain_snapshot().tip_hash, head.tip);
            assert!(chain.utxo_reader().get(&funding)?.is_none());
            assert!(
                chain
                    .utxo_reader()
                    .get(&OutPoint::new(valid.txs[1].txid(), 0))?
                    .is_some()
            );
            assert!(chain.begin_transition().is_ok());
            Ok(())
        }

        #[test]
        fn warm_assume_valid_start_over_an_accepted_checkpoint_reuses_the_durable_receipt()
        -> TestResult {
            let (mut chain, invalid, funding, checkpoint_dir) =
                commit_chain_with_checkpoint(OP_RETURN)?;
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing durable head"))?;
            let _dir = prepare_warm(&mut chain, checkpoint_dir, ValidationMode::AssumeValid)?;
            super::super::reconcile_at_boot(&chain)?;
            let tip = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing replay tip"))?;
            assert_eq!((tip.height, tip.hash), (head.height, head.tip));
            assert_eq!(tip.chain_tx_count.to_wire(), head.chain_tx_count);
            assert_eq!(chain.durable_head.load()?, Some(head));
            assert_eq!(chain.chain_snapshot().tip_hash, head.tip);
            assert!(chain.utxo_reader().get(&funding)?.is_none());
            assert!(
                chain
                    .utxo_reader()
                    .get(&OutPoint::new(invalid.txs[1].txid(), 0))?
                    .is_some()
            );
            assert!(chain.begin_transition().is_ok());
            Ok(())
        }

        // RCV-02
        #[test]
        fn full_start_over_an_assume_valid_commit_rebuilds_cold_and_rejects_the_invalid_script()
        -> TestResult {
            let (mut chain, invalid, funding, checkpoint_dir) =
                commit_chain_with_checkpoint(OP_RETURN)?;
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing durable head"))?;
            assert_eq!(
                chain.durable_head.load_attestation(&head)?,
                bitcoin_rs_storage::ScriptAttestation::AssumeValid,
                "the block committed with scripts skipped, so the head attests AssumeValid at best"
            );

            require_full_script_attestation(
                checkpoint_dir.path(),
                ValidationMode::AssumeValid,
                Some(&head),
                chain.durable_head.as_ref(),
                false,
            )?;
            assert!(!requires_full_revalidation(checkpoint_dir.path()));
            let warm = prepare_initial_chainstate(
                checkpoint_dir.path(),
                Network::Regtest,
                Some(&head),
                None,
            )?;
            assert_eq!(
                warm.resume_source,
                ResumeSource::Checkpoint,
                "an AssumeValid restart of the same datadir keeps the warm checkpoint replay"
            );

            require_full_script_attestation(
                checkpoint_dir.path(),
                ValidationMode::Full,
                Some(&head),
                chain.durable_head.as_ref(),
                false,
            )?;
            assert!(requires_full_revalidation(checkpoint_dir.path()));
            let dir = prepare_cold(&mut chain, Some(checkpoint_dir), ValidationMode::Full)?;
            let error = super::super::reconcile_at_boot(&chain)
                .err()
                .ok_or(TestError::Missing(
                    "a Full restart must execute the skipped script",
                ))?;
            assert!(
                matches!(error, ApplyError::Consensus(ConsensusError::Script { .. })),
                "{error:?}"
            );
            let tip = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing replay prefix"))?;
            assert_eq!(
                (tip.height, tip.hash),
                (100, invalid.header.prev_blockhash.0),
                "nothing publishes at the invalid height"
            );
            assert!(chain.utxo_reader().get(&funding)?.is_some());
            drop(dir);
            Ok(())
        }

        // RCV-02
        #[test]
        fn a_completed_full_cold_rebuild_attests_the_head_as_fully_executed() -> TestResult {
            let (mut chain, _valid, _funding, checkpoint_dir) =
                commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing durable head"))?;
            assert_eq!(
                chain.durable_head.load_attestation(&head)?,
                bitcoin_rs_storage::ScriptAttestation::AssumeValid
            );
            require_full_script_attestation(
                checkpoint_dir.path(),
                ValidationMode::Full,
                Some(&head),
                chain.durable_head.as_ref(),
                false,
            )?;
            let _dir = prepare_cold(&mut chain, Some(checkpoint_dir), ValidationMode::Full)?;
            super::super::reconcile_at_boot(&chain)?;
            assert_eq!(
                chain.durable_head.load_attestation(&head)?,
                bitcoin_rs_storage::ScriptAttestation::Full,
                "a cold rebuild executed every script, so the next Full start needs no rebuild"
            );
            Ok(())
        }

        // RCV-02
        #[test]
        fn full_start_over_a_pruned_datadir_names_the_way_out() -> TestResult {
            let (chain, _block, _funding, checkpoint_dir) =
                commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing durable head"))?;
            let error = require_full_script_attestation(
                checkpoint_dir.path(),
                ValidationMode::Full,
                Some(&head),
                chain.durable_head.as_ref(),
                true,
            )
            .err()
            .ok_or(TestError::Missing(
                "a pruned datadir cannot rebuild with full validation",
            ))?;
            assert!(
                matches!(
                    error,
                    crate::recovery::RecoveryError::PrunedDatadirNeedsFullValidation
                ),
                "{error}"
            );
            assert!(!requires_full_revalidation(checkpoint_dir.path()));
            Ok(())
        }

        // RCV-02
        #[test]
        fn full_start_over_a_validating_assumeutxo_head_names_the_way_out() -> TestResult {
            let (chain, _block, _funding, checkpoint_dir) =
                commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
            let head = chain
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing durable head"))?;
            let validating = bitcoin_rs_storage::DurableHead {
                assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Validating {
                    base_height: head.height,
                    base_hash: head.tip,
                    expected_hash_serialized:
                        bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[0x52; 32]),
                    chain_tx_count: head.chain_tx_count,
                    historical_height: 0,
                    historical_hash: Network::Regtest.genesis_block_hash(),
                    pending: None,
                    checkpoint: None,
                },
                ..head
            };
            let error = require_full_script_attestation(
                checkpoint_dir.path(),
                ValidationMode::Full,
                Some(&validating),
                chain.durable_head.as_ref(),
                false,
            )
            .err()
            .ok_or(TestError::UnexpectedSuccess(
                "a validating assumeutxo datadir cannot rebuild with full validation",
            ))?;
            assert!(
                matches!(
                    error,
                    crate::recovery::RecoveryError::AssumeUtxoValidatingNeedsFullValidation
                ),
                "{error}"
            );
            assert!(!requires_full_revalidation(checkpoint_dir.path()));
            require_full_script_attestation(
                checkpoint_dir.path(),
                ValidationMode::AssumeValid,
                Some(&validating),
                chain.durable_head.as_ref(),
                false,
            )?;
            Ok(())
        }
    }

    #[test]
    fn replay_refuses_zero_output_coinbase_and_preserves_committed_evidence() -> TestResult {
        // RCV-04
        for cold in [false, true] {
            for mode in [
                crate::ValidationMode::Full,
                crate::ValidationMode::AssumeValid,
            ] {
                let (mut chain, mut child) = restored_chainstate()?;
                chain.validation_mode = mode;
                child.txs[0].outputs.clear();
                child.header.merkle_root = crate::chain::regtest_fixture::merkle_root(&child.txs)
                    .ok_or(TestError::Missing("merkle root"))?;
                crate::chain::regtest_fixture::mine_block_to_declared_target(&mut child)?;
                let bodies = Arc::new(MemoryBodies::default());
                let genesis = Network::Regtest.genesis_block();
                bodies.persist_block_body(0, genesis.block_hash().0, &consensus_bytes(&genesis))?;
                let hash = child.block_hash().0;
                let bytes = consensus_bytes(&child);
                bodies.persist_block_body(1, hash, &bytes)?;
                let head = install_head(&mut chain, &child, Arc::clone(&bodies))?;
                let stats = chain.coin_stats.snapshot().to_bytes();
                if cold {
                    chain.applied_tip.store(None);
                    chain.coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
                }
                let result = super::reconcile_at_boot(&chain);
                assert!(
                    matches!(
                        result,
                        Err(ApplyError::Consensus(
                            bitcoin_rs_consensus::ConsensusError::EmptyOutputs
                        ))
                    ),
                    "cold={cold}, mode={mode:?}: {result:?}"
                );
                let tip = chain
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("valid prefix remains published"))?;
                assert_eq!((tip.height, tip.hash), (0, genesis.block_hash().0));
                assert_ne!(chain.chain_snapshot().tip_hash, hash);
                assert_eq!(chain.utxo.len(), 0);
                assert_eq!(chain.coin_stats.snapshot().to_bytes(), stats);
                assert_eq!(chain.durable_head.load()?, Some(head));
                assert_eq!(bodies.load_block_body(1, hash)?, Some(bytes));
                assert!(chain.undo_store.load_undo(1, hash)?.is_none());
                assert!(
                    chain.begin_transition().is_err(),
                    "replay failure closes admission"
                );
            }
        }
        Ok(())
    }

    fn restored_chainstate() -> TestResult<(Chainstate, Block)> {
        let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        let genesis_tip = seed_genesis(&handles)?;
        handles.coin_stats.finish_block(0, 1);
        let child = mined_child(BlockHash(genesis_tip.hash), 1)?;
        Ok((handles, child))
    }

    fn install_head(
        handles: &mut Chainstate,
        child: &Block,
        bodies: Arc<MemoryBodies>,
    ) -> Result<DurableHead, StorageError> {
        let hash = Hash256::from(child.block_hash());
        let head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 7,
            height: 1,
            tip: hash,
            chain_tx_count: 2,
            body_extent: None,
            undo_extent: None,
        };
        install_arbitrary_head(handles, &head, bodies)?;
        Ok(head)
    }

    fn install_arbitrary_head(
        handles: &mut Chainstate,
        head: &DurableHead,
        bodies: Arc<MemoryBodies>,
    ) -> Result<(), StorageError> {
        let durable = Arc::new(InMemoryDurableHeadStore::new());
        durable.commit(None, head, &CommitRecords::default())?;
        handles.durable_head = durable;
        handles.block_body_store = Some(bodies);
        Ok(())
    }

    // RCV-04, RCV-14
    #[test]
    fn committed_gap_replays_to_head_without_recommitting_it() -> TestResult {
        let (mut handles, child) = restored_chainstate()?;
        let bodies = Arc::new(MemoryBodies::default());
        bodies.persist_block_body(
            1,
            Hash256::from(child.block_hash()),
            &consensus_bytes(&child),
        )?;
        let head = install_head(&mut handles, &child, bodies)?;

        super::reconcile_at_boot(&handles)?;

        let landed = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::UnexpectedSuccess(
                "replay did not publish an applied tip",
            ))?;
        assert_eq!((landed.height, landed.hash), (head.height, head.tip));
        assert_eq!(
            landed.chain_tx_count,
            crate::chain::ChainTxCount::established(2)
        );
        assert_eq!(handles.durable_head.load()?, Some(head));
        assert_eq!(
            handles.durable_head.load()?.map(|head| head.commit_id),
            Some(7),
            "replay must consume the durable receipt rather than creating a new one"
        );
        Ok(())
    }

    #[test]
    fn replay_of_a_committed_gap_never_fires_the_staged_tip_hook() -> TestResult {
        let (mut handles, child) = restored_chainstate()?;
        let bodies = Arc::new(MemoryBodies::default());
        bodies.persist_block_body(
            1,
            Hash256::from(child.block_hash()),
            &consensus_bytes(&child),
        )?;
        let head = install_head(&mut handles, &child, bodies)?;

        let fires: Arc<Mutex<Vec<(Hash256, Hash256)>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&fires);
        handles
            .set_tip_staged(Arc::new(
                move |staged: &crate::chain::TipSnapshot, block: &BlockImage| {
                    recorder
                        .lock()
                        .push((staged.hash, Hash256::from(block.block_hash())));
                },
            ))
            .map_err(|_| TestError::HookAlreadyInstalled("staged-tip"))?;

        super::reconcile_at_boot(&handles)?;

        assert!(
            fires.lock().is_empty(),
            "replay of a committed gap schedules no speculative preparation work"
        );
        let landed = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::UnexpectedSuccess(
                "replay did not publish an applied tip",
            ))?;
        assert_eq!((landed.height, landed.hash), (head.height, head.tip));
        Ok(())
    }

    #[test]
    fn replay_publishes_the_receipt_certified_count() -> TestResult {
        let (mut handles, child) = restored_chainstate()?;
        let bodies = Arc::new(MemoryBodies::default());
        bodies.persist_block_body(
            1,
            Hash256::from(child.block_hash()),
            &consensus_bytes(&child),
        )?;
        let head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 7,
            height: 1,
            tip: Hash256::from(child.block_hash()),
            chain_tx_count: 5,
            body_extent: None,
            undo_extent: None,
        };
        install_arbitrary_head(&mut handles, &head, bodies)?;

        super::reconcile_at_boot(&handles)?;

        let landed = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::UnexpectedSuccess(
                "replay did not publish an applied tip",
            ))?;
        assert_eq!((landed.height, landed.hash), (head.height, head.tip));
        assert_eq!(
            landed.chain_tx_count,
            crate::chain::ChainTxCount::established(5),
            "the published count is the receipt's, not the derivation's"
        );
        Ok(())
    }

    #[test]
    fn replay_gap_skips_the_live_future_drift_recheck() -> TestResult {
        let (mut handles, mut child) = restored_chainstate()?;
        child.header.time = current_unix_seconds().saturating_add(4 * 60 * 60);
        crate::chain::regtest_fixture::mine_header_to_declared_target(&mut child.header)?;
        let bodies = Arc::new(MemoryBodies::default());
        bodies.persist_block_body(
            1,
            Hash256::from(child.block_hash()),
            &consensus_bytes(&child),
        )?;
        let head = install_head(&mut handles, &child, bodies)?;

        super::reconcile_at_boot(&handles)?;

        let landed = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::UnexpectedSuccess(
                "replay did not publish an applied tip",
            ))?;
        assert_eq!((landed.height, landed.hash), (head.height, head.tip));
        Ok(())
    }

    #[test]
    fn committed_gap_with_missing_body_fails_closed() -> TestResult {
        let (mut handles, child) = restored_chainstate()?;
        let head = install_head(&mut handles, &child, Arc::new(MemoryBodies::default()))?;

        let Err(error) = super::reconcile_at_boot(&handles) else {
            panic!("missing committed body must fail");
        };
        let ApplyError::DurableHeadGapUnrecoverable {
            head_tip,
            head_height,
            restored_tip,
            restored_height,
            ..
        } = error
        else {
            panic!("expected DurableHeadGapUnrecoverable, got {error:?}");
        };
        assert_eq!(head_tip, head.tip);
        assert_eq!(head_height, 1);
        assert_eq!(restored_tip, Some(Network::Regtest.genesis_block_hash()));
        assert_eq!(restored_height, Some(0));
        assert_eq!(
            handles
                .applied_tip
                .load_full()
                .map(|tip| (tip.height, tip.hash)),
            Some((0, Network::Regtest.genesis_block_hash()))
        );
        assert_eq!(handles.durable_head.load()?, Some(head));
        Ok(())
    }

    // RCV-15
    #[test]
    fn cold_chainstate_replays_head_chain_from_genesis() -> TestResult {
        let (mut handles, child) = restored_chainstate()?;
        handles.applied_tip.store(None);
        handles.coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
        let genesis = Network::Regtest.genesis_block();
        let bodies = Arc::new(MemoryBodies::default());
        bodies.persist_block_body(
            0,
            Hash256::from(genesis.block_hash()),
            &consensus_bytes(&genesis),
        )?;
        bodies.persist_block_body(
            1,
            Hash256::from(child.block_hash()),
            &consensus_bytes(&child),
        )?;
        let head = install_head(&mut handles, &child, bodies)?;

        super::reconcile_at_boot(&handles)?;

        let landed = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::UnexpectedSuccess(
                "cold replay did not publish an applied tip",
            ))?;
        assert_eq!((landed.height, landed.hash), (1, head.tip));
        assert_eq!(
            landed.chain_tx_count,
            crate::chain::ChainTxCount::established(2)
        );
        assert_eq!(
            handles.durable_head.load()?,
            Some(head),
            "replay must consume the durable receipt rather than creating a new one"
        );
        Ok(())
    }

    #[test]
    fn cold_chainstate_with_missing_genesis_body_fails_closed() -> TestResult {
        let (mut handles, child) = restored_chainstate()?;
        handles.applied_tip.store(None);
        handles.coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
        let bodies = Arc::new(MemoryBodies::default());
        bodies.persist_block_body(
            1,
            Hash256::from(child.block_hash()),
            &consensus_bytes(&child),
        )?;
        let head = install_head(&mut handles, &child, bodies)?;

        let Err(error) = super::reconcile_at_boot(&handles) else {
            panic!("a missing committed body must fail even on a cold chainstate");
        };
        assert!(matches!(
            error,
            ApplyError::DurableHeadGapUnrecoverable {
                restored_tip: None,
                restored_height: None,
                ..
            }
        ));
        assert!(handles.applied_tip.load_full().is_none());
        assert_eq!(handles.durable_head.load()?, Some(head));
        Ok(())
    }

    #[test]
    fn matching_durable_head_requires_no_replay() -> TestResult {
        let (mut handles, _) = restored_chainstate()?;
        let restored = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::Missing("restored tip missing"))?;
        let head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 3,
            height: restored.height,
            tip: restored.hash,
            chain_tx_count: 1,
            body_extent: None,
            undo_extent: None,
        };
        install_arbitrary_head(&mut handles, &head, Arc::new(MemoryBodies::default()))?;

        super::reconcile_at_boot(&handles)?;

        assert_eq!(handles.durable_head.load()?, Some(head));
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(restored.hash)
        );
        Ok(())
    }

    // RCV-14
    #[test]
    fn durable_head_at_or_below_restored_tip_is_not_a_replay_gap() -> TestResult {
        let (handles, child) = restored_chainstate()?;
        let restored = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::Missing("restored tip missing"))?;
        let head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 4,
            height: restored.height,
            tip: Hash256::from(child.block_hash()),
            chain_tx_count: 2,
            body_extent: None,
            undo_extent: None,
        };

        let Err(error) = super::replay_committed_gap(&handles, &head, Some(&restored)) else {
            panic!("head at restored height is not a publication gap");
        };
        assert!(matches!(
            error,
            ApplyError::DurableHeadGapUnrecoverable { .. }
        ));
        Ok(())
    }

    #[test]
    fn wide_authenticated_gap_replays_to_durable_head() -> TestResult {
        let (mut handles, first) = restored_chainstate()?;
        let width = crate::window_limits::DURABLE_HEAD_GROUP_BLOCKS + 1;
        let bodies = Arc::new(MemoryBodies::default());
        let mut tip_hash = Hash256::from(first.block_hash());
        bodies.persist_block_body(1, tip_hash, &consensus_bytes(&first))?;
        for height in 2..=u32::try_from(width)? {
            let block = mined_child(BlockHash(tip_hash), height)?;
            tip_hash = Hash256::from(block.block_hash());
            bodies.persist_block_body(height, tip_hash, &consensus_bytes(&block))?;
        }
        let head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 5,
            height: u32::try_from(width)?,
            tip: tip_hash,
            chain_tx_count: u64::try_from(width)? + 1,
            body_extent: None,
            undo_extent: None,
        };
        let certified = (head.height, head.tip, head.chain_tx_count);
        install_arbitrary_head(&mut handles, &head, bodies)?;

        super::reconcile_at_boot(&handles)?;

        let landed = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::UnexpectedSuccess(
                "wide replay did not publish an applied tip",
            ))?;
        assert_eq!(
            (landed.height, landed.hash, landed.chain_tx_count.to_wire()),
            certified
        );
        assert_eq!(handles.coin_stats.snapshot().tx_count, certified.2);
        assert_eq!(
            handles.durable_head.load()?.map(|head| head.commit_id),
            Some(5),
            "replay must consume the durable receipt rather than creating a new one"
        );
        Ok(())
    }

    #[test]
    fn committed_gap_body_must_hash_to_the_head_identity() -> TestResult {
        let (mut handles, child) = restored_chainstate()?;
        let restored = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::Missing("restored tip missing"))?;
        let claimed = Hash256::from_le_bytes(&[0x55; 32]);
        let bodies = Arc::new(MemoryBodies::default());
        bodies.persist_block_body(1, claimed, &consensus_bytes(&child))?;
        handles.block_body_store = Some(bodies);
        let head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 6,
            height: 1,
            tip: claimed,
            chain_tx_count: 2,
            body_extent: None,
            undo_extent: None,
        };

        let Err(error) = super::replay_committed_gap(&handles, &head, Some(&restored)) else {
            panic!("body/hash mismatch must fail");
        };
        assert!(matches!(
            error,
            ApplyError::DurableHeadGapUnrecoverable { .. }
        ));
        Ok(())
    }

    #[test]
    fn committed_gap_must_descend_from_restored_tip() -> TestResult {
        let (mut handles, child) = restored_chainstate()?;
        let restored = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::Missing("restored tip missing"))?;
        let mut wrong_restored = (*restored).clone();
        wrong_restored.hash = Hash256::from_le_bytes(&[0x44; 32]);
        let child_hash = Hash256::from(child.block_hash());
        let bodies = Arc::new(MemoryBodies::default());
        bodies.persist_block_body(1, child_hash, &consensus_bytes(&child))?;
        handles.block_body_store = Some(bodies);
        let head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 7,
            height: 1,
            tip: child_hash,
            chain_tx_count: 2,
            body_extent: None,
            undo_extent: None,
        };

        let Err(error) = super::replay_committed_gap(&handles, &head, Some(&wrong_restored)) else {
            panic!("head chain rooted elsewhere must fail");
        };
        assert!(matches!(
            error,
            ApplyError::DurableHeadGapUnrecoverable { .. }
        ));
        Ok(())
    }

    #[test]
    fn committed_gap_replay_failure_fails_closed() -> TestResult {
        let (mut handles, mut child) = restored_chainstate()?;
        let restored = handles
            .applied_tip
            .load_full()
            .ok_or(TestError::Missing("restored tip missing"))?;
        child.header.merkle_root = Hash256::from_le_bytes(&[0x77; 32]);
        let child_hash = Hash256::from(child.block_hash());
        let bodies = Arc::new(MemoryBodies::default());
        bodies.persist_block_body(1, child_hash, &consensus_bytes(&child))?;
        let head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 9,
            height: 1,
            tip: child_hash,
            chain_tx_count: 2,
            body_extent: None,
            undo_extent: None,
        };
        install_arbitrary_head(&mut handles, &head, bodies)?;

        let Err(error) = super::replay_committed_gap(&handles, &head, Some(&restored)) else {
            panic!("a gap body that fails apply must fail the replay");
        };
        assert!(
            handles.shutdown_reader().is_triggered(),
            "a failed replay must fail closed, got: {error}"
        );
        assert!(
            matches!(handles.begin_transition(), Err(ApplyError::Shutdown)),
            "admission must stay closed after a failed replay"
        );
        Ok(())
    }

    struct AttestFailHeadStore {
        inner: Arc<dyn DurableHeadStore>,
    }

    impl DurableHeadStore for AttestFailHeadStore {
        fn load(&self) -> Result<Option<DurableHead>, StorageError> {
            self.inner.load()
        }

        fn load_attestation(
            &self,
            head: &DurableHead,
        ) -> Result<bitcoin_rs_storage::ScriptAttestation, StorageError> {
            self.inner.load_attestation(head)
        }

        fn load_suffix_attestation(
            &self,
            head: &DurableHead,
        ) -> Result<bitcoin_rs_storage::ScriptAttestation, StorageError> {
            self.inner.load_suffix_attestation(head)
        }

        fn attest(
            &self,
            _head: &DurableHead,
            _level: bitcoin_rs_storage::ScriptAttestation,
        ) -> Result<(), StorageError> {
            Err(StorageError::Backend(
                "simulated attestation failure".to_owned(),
            ))
        }
    }

    // RCV-02
    #[test]
    fn cold_replay_attestation_failure_fails_closed() -> TestResult {
        let (mut handles, child) = restored_chainstate()?;
        handles.applied_tip.store(None);
        handles.coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
        let genesis = Network::Regtest.genesis_block();
        let bodies = Arc::new(MemoryBodies::default());
        bodies.persist_block_body(
            0,
            Hash256::from(genesis.block_hash()),
            &consensus_bytes(&genesis),
        )?;
        bodies.persist_block_body(
            1,
            Hash256::from(child.block_hash()),
            &consensus_bytes(&child),
        )?;
        install_head(&mut handles, &child, bodies)?;
        let inner = Arc::clone(&handles.durable_head);
        handles.durable_head = Arc::new(AttestFailHeadStore { inner });

        let Err(error) = super::reconcile_at_boot(&handles) else {
            panic!("a failed Full attestation must fail the rebuild");
        };
        assert!(
            matches!(error, ApplyError::DurableHeadCommit(_)),
            "the attestation failure surfaces unchanged, got: {error:?}"
        );
        assert!(
            handles.shutdown_reader().is_triggered(),
            "a failed Full attestation must fail closed"
        );
        assert!(
            matches!(handles.begin_transition(), Err(ApplyError::Shutdown)),
            "admission must stay closed after a failed attestation"
        );
        Ok(())
    }

    struct CrashFault;

    impl bitcoin_rs_storage::commit::CommitFault for CrashFault {
        fn before_commit(
            &self,
            _prefix: &bitcoin_rs_storage::AcceptedPrefix,
        ) -> Result<(), bitcoin_rs_storage::CommitError> {
            Err(bitcoin_rs_storage::CommitError::Storage(
                StorageError::Backend("simulated crash during head commit".to_owned()),
            ))
        }
    }

    // RCV-03
    proptest! {
    #![proptest_config(proptest::test_runner::Config {
        failure_persistence: Some(std::boxed::Box::new(
            proptest::test_runner::FileFailurePersistence::Direct(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/execution/regressions/durable/tests.txt"
            )),
        )),
        ..(ProptestConfig {
            cases: std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(256),
            ..ProptestConfig::default()
        })
    })]
        #[test]
        fn stateful_crash_window_leaves_state_exactly_before_or_after(
            fail_mode in 0_u8..=2,
            cold_boot in any::<bool>(),
        ) {
            let bodies: Arc<dyn BlockBodyStore> = Arc::new(MemoryBodies::default());
            let genesis = Network::Regtest.genesis_block();
            let genesis_hash = Hash256::from(genesis.block_hash());
            bodies
                .persist_block_body(0, genesis_hash, &consensus_bytes(&genesis))
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;

            let genesis_head = DurableHead {
                assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 1,
                height: 0,
                tip: genesis_hash,
                chain_tx_count: 1,
                body_extent: None,
                undo_extent: None,
            };

            let child1 = mined_child(BlockHash(genesis_hash), 1)
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            let child1_hash = Hash256::from(child1.block_hash());
            let child_coinbase_txid = child1.txs[0].txid();
            let child_coinbase_value = child1.txs[0].outputs[0].value.to_sat();
            bodies
                .persist_block_body(1, child1_hash, &consensus_bytes(&child1))
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;

            let store = Arc::new(bitcoin_rs_storage::MemoryKvStore::new());
            let mut chain = handles_with_store(
                Network::Regtest,
                Arc::new(UtxoSet::new()),
                Arc::clone(&store),
            );
            chain
                .commit_authority
                .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: None,
                    next_head: genesis_head,
                    undo_rows: Vec::new(),
                    body_rows: Vec::new(),
                    attestation: None,
                    coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                })
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            let genesis_tip = seed_genesis(&chain).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            chain.block_body_store = Some(Arc::clone(&bodies));

            if fail_mode == 0 {
                chain.commit_authority.set_fault(Arc::new(CrashFault));
            }

            let payload = bitcoin_rs_consensus::primitives::BlockImage::from_local(child1);
            let apply_result = chain.apply_block(&payload);

            let prior_head = genesis_head;

            if fail_mode == 0 {
                prop_assert!(apply_result.is_err(), "write index failure must return error");
            } else {
                prop_assert!(apply_result.is_ok(), "clean write must succeed");
            }

            let committed_head = chain
                .durable_head
                .load()
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            let mut reopened = handles_with_store(
                Network::Regtest,
                Arc::new(UtxoSet::new()),
                Arc::clone(&store),
            );
            let _ = seed_genesis(&reopened).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            reopened.block_body_store = Some(bodies);
            if cold_boot {
                reopened.applied_tip.store(None);
                reopened.coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
            } else if fail_mode == 1 {
                reopened.applied_tip.store(Some(Arc::new(genesis_tip)));
            } else {
                reopened.applied_tip.store(chain.applied_tip.load_full());
            }
            super::reconcile_at_boot(&reopened).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;

            let recovered_tip = reopened
                .applied_tip_snapshot()
                .ok_or_else(|| TestCaseError::fail("recovered tip must exist"))?;
            let recovered_head = reopened
                .durable_head
                .load()
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?
                .ok_or_else(|| TestCaseError::fail("recovered head must exist"))?;

            prop_assert_eq!(recovered_tip.height, recovered_head.height);
            prop_assert_eq!(recovered_tip.hash, recovered_head.tip);
            prop_assert_eq!(
                Some(recovered_head),
                committed_head,
                "boot replay must leave the durable head exactly as it was committed"
            );

            let is_state_before = recovered_head == prior_head
                && recovered_tip.height == 0
                && recovered_tip.hash == genesis_hash;
            let is_state_after = recovered_head.height == 1
                && recovered_head.tip == child1_hash
                && recovered_tip.height == 1
                && recovered_tip.hash == child1_hash;

            let child_coinbase_key = CoinKey(child_coinbase_txid.0.to_le_bytes());
            let authoritative_coin = store
                .get(ColumnFamily::Coins, child_coinbase_key.as_bytes())
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            let reopened_coin = reopened
                .coins
                .get(&child_coinbase_key)
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            prop_assert_eq!(
                reopened_coin.is_some(),
                is_state_after,
                "reopened coin view must expose the child coinbase exactly when the block is committed"
            );
            prop_assert_eq!(
                authoritative_coin.is_some(),
                is_state_after,
                "authoritative KV must hold the child coinbase row exactly when the block is committed"
            );
            if is_state_after {
                let committed_bytes = authoritative_coin.as_ref().ok_or_else(|| {
                    TestCaseError::fail("committed coin row missing from authoritative store")
                })?;
                prop_assert_eq!(
                    reopened_coin.as_deref(),
                    authoritative_coin.as_deref(),
                    "reopened coin store must read the committed authoritative row unchanged"
                );
                let record = UtxoRecord::from_encoded(committed_bytes.to_vec().into_boxed_slice())
                    .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
                prop_assert_eq!(record.txid(), child_coinbase_txid.0);
                let coinbase_out = record
                    .find_output(0)
                    .ok_or_else(|| TestCaseError::fail("committed coinbase record lost output 0"))?;
                prop_assert_eq!(coinbase_out.height, 1_u32);
                prop_assert!(coinbase_out.coinbase, "committed coinbase row must be marked coinbase");
                prop_assert_eq!(coinbase_out.value, child_coinbase_value);
            }

            if fail_mode == 0 {
                prop_assert!(
                    is_state_before,
                    "fail mode 0 refuses the head commit, so reopen must land exactly before, got height {}",
                    recovered_head.height
                );
            } else {
                prop_assert!(
                    is_state_after,
                    "fail modes 1 and 2 acknowledge the head commit, so reopen must land exactly after, got height {}",
                    recovered_head.height
                );
            }
        }
    }
    // CMT-06
    #[test]
    fn rewind_one_step_removes_creations_from_block_bytes() -> TestResult {
        let bodies: Arc<MemoryBodies> = Arc::new(MemoryBodies::default());
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        bodies.persist_block_body(0, genesis_hash, &consensus_bytes(&genesis))?;
        let genesis_head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 0,
            tip: genesis_hash,
            chain_tx_count: 1,
            body_extent: None,
            undo_extent: None,
        };
        let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        chain
            .commit_authority
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: None,
                next_head: genesis_head,
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(|_| TestError::Missing("commit prefix"))?;
        let _ = seed_genesis(&chain)?;
        let shared_bodies = Arc::clone(&bodies);
        let body_store: Arc<dyn BlockBodyStore> = shared_bodies;
        chain.block_body_store = Some(body_store);
        let child = mined_child(BlockHash(genesis_hash), 1)?;
        let child_hash = Hash256::from(child.block_hash());
        let created = OutPoint::new(child.txs[0].txid(), 0);
        if chain.utxo_reader().get(&created)?.is_some() {
            return Err(TestError::Missing("creation must be absent before connect"));
        }
        bodies.persist_block_body(1, child_hash, &consensus_bytes(&child))?;
        chain.apply_block(&BlockImage::from_local(child.clone()))?;
        if chain.utxo_reader().get(&created)?.is_none() {
            return Err(TestError::Missing("creation must be present after connect"));
        }
        let applied = chain
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("applied tip"))?;
        if applied.height != 1 || applied.hash != child_hash {
            return Err(TestError::Missing("child must be the applied tip"));
        }
        super::rewind_one_step(&chain, &genesis_head, &applied)?;
        let rewound = chain
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("rewound tip"))?;
        if rewound.height != 0 || rewound.hash != genesis_hash {
            return Err(TestError::Missing("rewind must publish the parent tip"));
        }
        if chain.utxo_reader().get(&created)?.is_some() {
            return Err(TestError::Missing(
                "coin set after rewind must equal the set before connect",
            ));
        }
        Ok(())
    }
}
