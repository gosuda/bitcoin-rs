//! Orders [`bitcoin_rs_utxo::rollback_block`] against the journal, the
//! durable head, and publication.

use super::Chainstate;
use super::DisconnectOutcome;
use super::DisconnectPlan;
use super::durable::commit_disconnect_head;
use super::publication::certified_rewind;
use super::publication::publish_disconnect;
use super::publication::tx_count_delta_for;
use crate::error::ApplyError;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_utxo::{BlockRollback, RollbackError, load_block_undo, rollback_block};

pub(super) fn plan_disconnect(
    handles: &Chainstate,
    block: &Block,
    block_hash: Hash256,
) -> core::result::Result<DisconnectPlan, ApplyError> {
    let applied = handles
        .applied_tip
        .load_full()
        .ok_or(ApplyError::DisconnectNotTip {
            hash: block_hash,
            tip: block_hash,
        })?;
    // Undo and index rollback are keyed by height; only the tip may name it.
    let height = applied.height;
    if applied.hash != block_hash {
        return Err(ApplyError::DisconnectNotTip {
            hash: block_hash,
            tip: applied.hash,
        });
    }

    // The head must already certify this block: a disconnect advances the
    // durable head from a known commit point, and any other tip is lineage
    // divergence that refusing preserves untouched.
    let head = handles
        .durable_head
        .load()
        .map_err(ApplyError::DurableHeadCommit)?;
    if head.as_ref().map(|head| head.tip) != Some(block_hash) {
        return Err(ApplyError::DisconnectOffDurableHead {
            hash: block_hash,
            head: head.map(|head| head.tip),
        });
    }

    // An altered body under a matching header would undo transactions the
    // block never contained; txid-level merkle check also catches a duplicated
    // final transaction that `check_merkle_root` alone misses.
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
    bitcoin_rs_consensus::verify_merkle_root_with_txids(block, &txids)
        .map_err(|_| ApplyError::DisconnectBodyMismatch { hash: block_hash })?;

    let (parent_tip, parent_prev_hash, parent_chain_tx_count) = {
        let tree = handles.block_tree.read();
        let node = tree.node(applied.tip_id)?;
        let parent_id = node.parent.ok_or(ApplyError::DisconnectNotTip {
            hash: block_hash,
            tip: applied.hash,
        })?;
        let parent = tree.node(parent_id)?;
        let parent_prev_hash = match parent.parent {
            Some(grandparent_id) => tree.node(grandparent_id)?.hash,
            None => Hash256::default(),
        };
        (
            TipSnapshot {
                tip_id: parent_id,
                height: parent.height,
                chainwork: parent.chainwork,
                hash: parent.hash,
            },
            parent_prev_hash,
            parent.chain_tx_count,
        )
    };

    let undo = load_block_undo(handles.undo_store.as_ref(), height, block_hash)?;

    // Coinstats rewinds inside the marker fence; refuse its bad inputs here
    // while refusal is still free.
    let tx_count_delta = tx_count_delta_for(block);
    handles
        .coin_stats
        .check_rewind(height, tx_count_delta)
        .map_err(ApplyError::CoinStatsRewind)?;

    Ok(DisconnectPlan {
        parent_tip,
        parent_prev_hash,
        parent_chain_tx_count,
        undo,
        height,
        tx_count_delta,
    })
}

/// Caller holds admission then `chain_transition`, in that order.
pub(super) fn disconnect_block_admitted(
    handles: &Chainstate,
    block: &Block,
) -> core::result::Result<DisconnectOutcome, crate::DisconnectError> {
    let block_hash = block.block_hash().0;
    let DisconnectPlan {
        parent_tip,
        parent_prev_hash,
        parent_chain_tx_count,
        undo,
        height,
        tx_count_delta,
    } = plan_disconnect(handles, block, block_hash)
        .map_err(|error| crate::DisconnectError::Refused(Box::new(error)))?;

    let poison = |error| {
        handles.admission.close_permanently();
        error
    };
    let fatal = |source: ApplyError| {
        poison(crate::DisconnectError::Fatal {
            hash: block_hash,
            height,
            source: Box::new(source),
        })
    };
    // Fenced per disconnect, not per reorg: an interrupted switch leaves a
    // consistent lower tip. `Refused` touched nothing; the rest may have torn
    // state and poison admission for recovery.
    rollback_block(
        handles.undo_store.as_ref(),
        handles.utxo.as_ref(),
        handles.coin_stats.as_ref(),
        &BlockRollback {
            hash: block_hash,
            height,
            parent_height: parent_tip.height,
            tx_count_delta,
        },
        &undo,
    )
    .map_err(|error| match error {
        RollbackError::Refused(source) => {
            crate::DisconnectError::Refused(Box::new(ApplyError::UndoPersistence(source)))
        }
        RollbackError::Utxo(source) => fatal(ApplyError::UtxoCommit(source)),
        RollbackError::CoinStats(source) => fatal(ApplyError::CoinStatsRewind(source)),
        RollbackError::Marker(source) => fatal(ApplyError::UndoPersistence(source)),
    })?;
    // Journal rewinds before the head advances so a kill between the two
    // leaves the head as high-water mark.
    let journal_rewound = handles.journal.as_ref().is_some_and(|journal| {
        let rewound = journal.lock().rewind_to(
            parent_tip.height,
            parent_tip.hash.to_le_bytes(),
            parent_prev_hash.to_le_bytes(),
            parent_chain_tx_count.to_wire(),
        );
        rewound
            .map_err(|error| {
                metrics::counter!("node.chainstate_journal.reorg_failures").increment(1);
                tracing::warn!(
                    height = parent_tip.height,
                    hash = %parent_tip.hash,
                    %error,
                    "chainstate journal fork-head rewrite failed; retaining disconnect marker"
                );
            })
            .is_ok()
    });
    // Durable before published: the head batch names the rewound count one
    // step ahead of the tip that carries it, and both stores land the value
    // the commit certified.
    let rewound = certified_rewind(handles.applied_chain_tx_count(), tx_count_delta);
    commit_disconnect_head(handles, &parent_tip, block_hash, rewound.to_wire())
        .map_err(fatal)?;
    publish_disconnect(handles, &parent_tip, rewound);
    // A checkpoint-restored parent node still carries an unknown count even
    // though the rewind just re-derived it; store the value on the node too
    // so a later reorg reconnect derives the child's cumulative count from it
    // instead of propagating unknown.
    handles
        .block_tree
        .write()
        .restore_chain_tx_count(parent_tip.tip_id, rewound)
        .map_err(|error| fatal(ApplyError::Chain(error)))?;
    if journal_rewound {
        handles.undo_store.disarm_disconnect().map_err(|error| {
            poison(crate::DisconnectError::MarkerStuck {
                hash: block_hash,
                height,
                source: Box::new(ApplyError::UndoPersistence(error)),
            })
        })?;
    }

    // Without a journal rewind the marker stays set: a crash could restore a
    // checkpoint still holding this block, and `write_clean_checkpoint`
    // disarms it only after publishing the rolled-back set.
    Ok(DisconnectOutcome {
        parent_tip,
        hash: block_hash,
        restored_parents: undo
            .restores()
            .iter()
            .map(|restored| restored.outpoint.txid)
            .collect(),
    })
}

/// Rewinds the journal fork head to the disconnect's parent. A failed rewind
/// keeps the disconnect marker for recovery and reports `false`.
fn rewind_journal_to_parent(
    handles: &Chainstate,
    parent_tip: &TipSnapshot,
    parent_prev_hash: Hash256,
    parent_chain_tx_count: u64,
) -> bool {
    let Some(journal) = handles.journal.as_ref() else {
        return false;
    };
    journal
        .lock()
        .rewind_to(
            parent_tip.height,
            parent_tip.hash.to_le_bytes(),
            parent_prev_hash.to_le_bytes(),
            parent_chain_tx_count,
        )
        .map_err(|error| {
            metrics::counter!("node.chainstate_journal.reorg_failures").increment(1);
            tracing::warn!(
                height = parent_tip.height,
                hash = %parent_tip.hash,
                %error,
                "chainstate journal fork-head rewrite failed; retaining disconnect marker"
            );
        })
        .is_ok()
}
