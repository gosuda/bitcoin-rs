//! Preflighted tip disconnection sequenced across the node's stores.
//!
//! The marker-fenced UTXO rollback itself is [`bitcoin_rs_utxo::undo`]; this
//! module orders it against the journal, the durable head, and publication.

use super::ChainChangeProof;
use super::Chainstate;
use super::DisconnectOutcome;
use super::DisconnectPlan;
use super::durable::commit_disconnect_head;
use super::publication::begin_applied_publication;
use super::publication::rewind_chain_tx_count;
use super::publication::rewound_chain_tx_count;
use super::publication::tx_count_delta_for;
use crate::apply::error::ApplyError;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_utxo::{BlockRollback, RollbackError, load_block_undo, rollback_block};
use std::sync::Arc;

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
    // The height is read from the snapshot, never from the caller. A caller
    // that could pass one would be able to disagree with the tip, and the undo
    // key is keyed by it. The index worker also keys its rollback by height.
    let height = applied.height;
    if applied.hash != block_hash {
        return Err(ApplyError::DisconnectNotTip {
            hash: block_hash,
            tip: applied.hash,
        });
    }

    // The header hash proves the caller named the right block; it does not
    // prove they handed over that block's transactions. An altered body under
    // a matching header would roll the UTXO set back over transactions the
    // block never contained.
    //
    // Computing txids here and verifying the merkle root with them catches
    // mutation (a duplicate final transaction on an odd count) that
    // `check_merkle_root` alone misses.
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

    // The coinstats rewind itself runs inside the marker-fenced rollback, after
    // the UTXO undo. This is the only place its preconditions can be checked
    // while a refusal is still free.
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

/// Disconnects one block while the caller holds admission and `chain_transition`.
///
/// The caller MUST hold both guards in admission-then-transition order.
#[allow(clippy::too_many_lines)]
pub(super) fn disconnect_block_admitted(
    handles: &Chainstate,
    block: &Block,
    _proof: &ChainChangeProof<'_>,
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
    // Marker-fenced per disconnect, not per reorg: a switch interrupted between
    // disconnects leaves a consistent lower tip that connects forward. A
    // `Refused` touched nothing; anything else may have torn state and poisons
    // admission so only recovery reconciles it. The marker stays `RolledBack`
    // until the checkpoint below; the head then advances its commit id onto
    // the parent tip (a reorg lowers height, never commit id).
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
    .map_err(|error| {
        let fatal = |source| {
            poison(crate::DisconnectError::Fatal {
                hash: block_hash,
                height,
                source: Box::new(source),
            })
        };
        match error {
            RollbackError::Refused(source) => {
                crate::DisconnectError::Refused(Box::new(ApplyError::UndoPersistence(source)))
            }
            RollbackError::Utxo(source) => fatal(ApplyError::UtxoCommit(source)),
            RollbackError::CoinStats(source) => fatal(ApplyError::CoinStatsRewind(source)),
            RollbackError::Marker(source) => fatal(ApplyError::UndoPersistence(source)),
        }
    })?;
    // The journal follows the durable head, never leads it: rewind the
    // derived journal onto the parent first, then advance the head, so a
    // kill between the two leaves the head as the high-water mark.
    let journal_rewound = handles.journal.as_ref().is_some_and(|journal| {
        let rewind_result = {
            let mut journal = journal.lock();
            journal.rewind_to(
                parent_tip.height,
                parent_tip.hash.to_le_bytes(),
                parent_prev_hash.to_le_bytes(),
                parent_chain_tx_count,
            )
        };
        match rewind_result {
            Ok(()) => true,
            Err(error) => {
                metrics::counter!("node.chainstate_journal.reorg_failures").increment(1);
                tracing::warn!(
                    height = parent_tip.height,
                    hash = %parent_tip.hash,
                    %error,
                    "chainstate journal fork-head rewrite failed; retaining disconnect marker"
                );
                false
            }
        }
    });
    let parent = parent_tip.clone();
    commit_disconnect_head(
        handles,
        &parent,
        block_hash,
        rewound_chain_tx_count(handles, tx_count_delta),
    )
    .map_err(|error| {
        poison(crate::DisconnectError::Fatal {
            hash: block_hash,
            height,
            source: Box::new(error),
        })
    })?;

    {
        let _publication = begin_applied_publication(handles);
        handles
            .applied_tip
            .store(Some(Arc::new(parent_tip.clone())));
        handles
            .chain_events
            .record(parent_tip.height, parent_tip.hash);
        rewind_chain_tx_count(handles, tx_count_delta);
    }
    if journal_rewound {
        handles.undo_store.disarm_disconnect().map_err(|error| {
            poison(crate::DisconnectError::MarkerStuck {
                hash: block_hash,
                height,
                source: Box::new(ApplyError::UndoPersistence(error)),
            })
        })?;
    }

    // Without a durable journal fork transition, the marker deliberately stays set here.
    //
    // The authoritative rollback completed in memory, but it is not durable.
    // A crash can restore a checkpoint whose UTXO set and tip still contain
    // this block. TxIndex is outside this transaction and reconciles from its
    // own atomic watermark after restart.
    //
    // [`NodeState::write_clean_checkpoint`] clears the marker only after it
    // publishes the rolled-back UTXO set and tip.
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
