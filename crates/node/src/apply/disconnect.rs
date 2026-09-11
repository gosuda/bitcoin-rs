//! Preflighted tip disconnection and the durable rollback-marker transaction.

use super::ChainChangeProof;
use super::Chainstate;
use super::DisconnectOutcome;
use super::DisconnectPlan;
use super::publication::begin_applied_publication;
use super::publication::rewind_chain_tx_count;
use super::publication::tx_count_delta_for;
use crate::apply::error::ApplyError;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
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

    let encoded = handles
        .undo_store
        .load_undo(height, block_hash)
        .map_err(ApplyError::UndoRead)?
        .ok_or(ApplyError::UndoRecordMissing {
            hash: block_hash,
            height,
        })?;
    let undo = bitcoin_rs_utxo::undo_codec::decode(&encoded, block_hash).map_err(|error| {
        ApplyError::UndoRecordUnreadable {
            hash: block_hash,
            reason: error.to_string(),
        }
    })?;

    // The coinstats rewind itself has to run after `undo_block`, because the
    // per-coin fields ride the UTXO change listener. This is the only place its
    // preconditions can be checked while a refusal is still free.
    let tx_count_delta = tx_count_delta_for(block);
    let stats = handles.coin_stats.snapshot();
    if stats.height != height {
        return Err(ApplyError::CoinStatsRewind(
            bitcoin_rs_utxo::stats::CoinStatsRewindError::HeightMismatch {
                expected: height,
                found: stats.height,
            },
        ));
    }
    if stats.tx_count < tx_count_delta {
        return Err(ApplyError::CoinStatsRewind(
            bitcoin_rs_utxo::stats::CoinStatsRewindError::TxCountUnderflow {
                tx_count: stats.tx_count,
                tx_delta: tx_count_delta,
            },
        ));
    }

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

    // Armed before the first mutation and cleared after the last, so the window
    // it covers is exactly the window in which state can be torn. Errors are not
    // what this guards against; a crash is. A crash writes no error anywhere,
    // and the marker is the only thing that survives it.
    //
    // Above the UTXO undo, not below it: once that undo commits, a crash
    // between it and the arming would leave the UTXO set rolled back while the
    // tip still names the block.
    //
    // Deliberately per-disconnect rather than per-reorg: each disconnect commits
    // fully, so a branch switch interrupted BETWEEN disconnects leaves a
    // consistent chain at a lower tip, which is recoverable by connecting
    // forward. Holding the marker across a whole switch would refuse startup for
    // that case and force a needless reindex.
    // Read before arming. A branch switch disconnects several blocks in a row,
    // and arming overwrites the marker, so an earlier disconnect's `RolledBack`
    // debt — still owed a checkpoint — would be destroyed by the next arm and
    // then cleared by a refusal. Loading the marker first lets a read failure
    // refuse before any mutation.
    handles
        .undo_store
        .load_disconnect_marker()
        .map_err(|error| {
            crate::DisconnectError::Refused(Box::new(ApplyError::UndoPersistence(error)))
        })?;
    handles
        .undo_store
        .arm_disconnect(height, block_hash)
        .map_err(|error| {
            crate::DisconnectError::Refused(Box::new(ApplyError::UndoPersistence(error)))
        })?;
    let poison = |error| {
        handles.admission.close_permanently();
        error
    };
    // Past this line every failure is `Fatal`. The UTXO commit walks shards and
    // can stop part-way, so from here some state is rolled back and some is
    // not.
    handles.utxo.undo_block(&undo).map_err(|error| {
        poison(crate::DisconnectError::Fatal {
            hash: block_hash,
            height,
            source: Box::new(ApplyError::UtxoCommit(error)),
        })
    })?;

    // The per-coin coinstats fields need nothing here: `coin_stats` is the
    // `UtxoSet` change listener, so `undo_block` already drove them in reverse.
    // The block-level fields are not part of that, because `finish_block` sets
    // them directly on connect.
    handles
        .coin_stats
        .rewind_block(height, parent_tip.height, tx_count_delta)
        .map_err(|error| {
            poison(crate::DisconnectError::Fatal {
                hash: block_hash,
                height,
                source: Box::new(ApplyError::CoinStatsRewind(error)),
            })
        })?;

    {
        let _publication = begin_applied_publication(handles);
        handles
            .applied_tip
            .store(Some(Arc::new(parent_tip.clone())));
        handles.chain_events.record(
            crate::state::HintKind::Disconnected,
            parent_tip.height,
            parent_tip.hash,
        );
        rewind_chain_tx_count(handles, tx_count_delta);
    }
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

    // The rollback finished in memory, so the marker moves to `RolledBack`.
    // It stays set: a checkpoint has not captured this yet.
    handles
        .undo_store
        .complete_disconnect(height, block_hash)
        .map_err(|error| {
            poison(crate::DisconnectError::MarkerStuck {
                hash: block_hash,
                height,
                source: Box::new(ApplyError::UndoPersistence(error)),
            })
        })?;

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
